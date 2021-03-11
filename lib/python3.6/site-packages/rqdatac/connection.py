# -*- coding: utf-8 -*-
import socket
import select

import warnings

from rqdatac.share.protocol import MSG_TYPE, SERIALIZATION_TYPE, COMPRESSION_METHOD, HEADER_LENGTH
from rqdatac.share.errors import get_error
from rqdatac.share.codec import snappy, brotli, msgpack, unpack_header, pack_one, unpack_one
from rqdatac.utils import connection_error

if brotli is not None:
    DEFAULT_COMPRESSION_METHOD = COMPRESSION_METHOD.BROTLI
elif snappy is not None:
    DEFAULT_COMPRESSION_METHOD = COMPRESSION_METHOD.SNAPPY
else:
    DEFAULT_COMPRESSION_METHOD = COMPRESSION_METHOD.ZLIB

if msgpack is None:
    DEFAULT_SERIALIZER_TYPE = SERIALIZATION_TYPE.JSON
else:
    DEFAULT_SERIALIZER_TYPE = SERIALIZATION_TYPE.MSGPACK


if hasattr(select, 'poll'):
    def _is_connection_normal(sock):
        poll = select.poll()
        poll.register(sock, select.POLLIN | select.POLLERR)
        return not poll.poll(0)
else:
    def _is_connection_normal(sock):
        readable, _, exceptional = select.select([sock], [], [sock], 0)
        return not readable and not exceptional


class ProtocolError(connection_error):
    pass


class Connection:
    sock_factory = staticmethod(socket.create_connection)

    @staticmethod
    def set_sock_factory(func):
        Connection.sock_factory = staticmethod(func)

    def __init__(self, sock, auth):
        self._socket = sock  # type: socket.socket
        self._sf = sock.makefile("rb", 128 * 1024)
        self._compression_method = DEFAULT_COMPRESSION_METHOD
        self._serializer_type = SERIALIZATION_TYPE.MSGPACK
        self._auth_info = auth.copy()
        self._auth_info["node"] = self._socket.getsockname()[0]
        self._do_auth(self._auth_info)

    def set_timeout(self, timeout):
        self._socket.settimeout(timeout)

    def is_normal(self):
        return _is_connection_normal(self._socket)

    def _read_one_packet(self):
        header = self._sf.read(HEADER_LENGTH)
        if len(header) != HEADER_LENGTH:
            if len(header) == 0:
                raise ProtocolError("Disconnected from the remote server")
            raise ProtocolError("incomplete header, %r" % len(header))

        mt, st, cm, length = unpack_header(header)
        if mt not in MSG_TYPE:
            raise ProtocolError("invalid message type: {}".format(mt))
        if not SERIALIZATION_TYPE.RAW <= st <= SERIALIZATION_TYPE.MSGPACK:
            raise ProtocolError("invalid serializer type: {}".format(st))
        if not COMPRESSION_METHOD.NONE <= cm <= COMPRESSION_METHOD.BROTLI:
            raise ProtocolError("invalid compression method: {}".format(cm))

        if length > 0:
            body = self._sf.read(length)
            if len(body) != length:
                raise ProtocolError("incomplete body")
            try:
                body = unpack_one(body, st, cm)
            except Exception as e:
                raise ProtocolError(repr(e))
            if mt == MSG_TYPE.ERROR:
                code, msg = body
                raise get_error(code)(msg)
            return mt, body

        return mt, None

    def _do_auth(self, auth):
        auth_body = pack_one(
            auth, MSG_TYPE.HANDSHAKE, DEFAULT_SERIALIZER_TYPE, DEFAULT_COMPRESSION_METHOD, force_compress=True
        )
        self._socket.sendall(auth_body)
        msg_type, body = self._read_one_packet()
        if msg_type != MSG_TYPE.HANDSHAKE:
            raise ProtocolError(
                "handshake message expected while {} received".format(MSG_TYPE[msg_type])
            )
        elif body is not None:
            warnings.warn(body)

    def close(self):
        self._sf.close()
        self._socket.close()

    def execute(self, method, *args, **kwargs):
        request_body = pack_one(
            (method, args, kwargs),
            MSG_TYPE.REQUEST,
            DEFAULT_SERIALIZER_TYPE,
            DEFAULT_COMPRESSION_METHOD,
        )
        self._socket.sendall(request_body)
        msg_type, body = self._read_one_packet()
        if msg_type == MSG_TYPE.RESPONSE:
            return body

        if msg_type != MSG_TYPE.STREAM_START:
            raise ProtocolError('got {} when STREAM_START expected'.format(MSG_TYPE[msg_type]))

        msg_type, body = self._read_one_packet()
        if msg_type == MSG_TYPE.STREAM_END:
            return []
        elif msg_type == MSG_TYPE.TABLE:
            return self.table_unpack(body)
        elif msg_type == MSG_TYPE.TABLE2:
            return self.table2_unpack(body)
        elif msg_type == MSG_TYPE.FEED:
            return self.feed_unpack(body)
        else:
            raise ProtocolError("unexpected message in stream: {}".format(MSG_TYPE[msg_type]))

    def feed_unpack(self, first):
        ret = list(first)
        while True:
            msg_type, body = self._read_one_packet()
            if msg_type == MSG_TYPE.STREAM_END:
                return ret
            elif msg_type == MSG_TYPE.FEED:
                ret.extend(body)
            else:
                raise ProtocolError(
                    "unexpected message in feed stream: {}".format(MSG_TYPE[msg_type])
                )

    def table_unpack(self, first):
        ret = []
        keys = first[0]
        ret.extend(dict(zip(keys, row)) for row in first[1:])
        while True:
            msg_type, body = self._read_one_packet()
            if msg_type == MSG_TYPE.STREAM_END:
                return ret
            elif msg_type == MSG_TYPE.TABLE:
                ret.extend(dict(zip(keys, row)) for row in body)
            else:
                raise ProtocolError(
                    "unexpected message in table stream: {}".format(MSG_TYPE[msg_type])
                )

    def table2_unpack(self, first):
        data = []
        head = first[0]
        data.extend(row for row in first[1:])
        while True:
            msg_type, body = self._read_one_packet()
            if msg_type == MSG_TYPE.STREAM_END:
                return head, data
            elif msg_type == MSG_TYPE.TABLE2:
                data.extend(row for row in body)
            else:
                raise ProtocolError(
                    "unexpected message in table2 stream: {}".format(MSG_TYPE[msg_type])
                )
