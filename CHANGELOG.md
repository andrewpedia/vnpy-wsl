# 2.1.9.1版本

## 修复
1. 修复RestClient中，因为pyopenssl.extract_from_urllib3引起的兼容性问题

## 调整
1. 调整OptionMaster模块中，期权链数据结构搜索平值行权价的算法，不再依赖标的物合约

## 新增
1. 新增OptionMaster模块使用合成期货作为定价标的合约的功能


# 2.1.9版本

## 修复
1. 修复BarGenerator的小时线合成时，出现同一个小时的K线重复推送两次的问题
2. 修复遗传算法优化时，因为lru_cache缓存导致的新一轮优化结果不变的问题
3. 修复RestClient发起请求时，由于requests库底层使用OpenSSL导致的WinError 10054 WSAECONNRESET的问题
4. 修复okexf、okexs、okexo三个接口收取TICK行情时，盘口数据解析错误的问题
5. 修复程序中频繁捕捉到异常时，异常捕捉对话框反复执行导致卡死的问题
6. 修复币安的现货和合约接口请求抛出SSLError异常时，未捕捉导致程序卡死的问题
7. 修复活动委托监控组件ActiveOrderMonitor，保存CSV时会将所有委托数据一起保存的问题
8. 修复XtpGateway重复发起登录操作时，出现的系统崩溃问题
9. 修复XtpGateway的股票市价委托类型映射错误问题
10. 修复DeribitGateway中对于Stop Market类型委托的支持问题，同时过滤掉Stop Limit类型委托
11. 修复BinancesGateway中，由于成交数量浮点数精度问题导致的上层应用模块（CtaStrategy）数据计算错误
12. 修复BinancesGateway中，由于合约持仓类型（应该是净仓，而非多空仓）错误，导致的上层应用模块（SpreadTrading）数据计算错误
13. 修复HuobisGateway中，初始化查询活动委托时，由于请求过快导致的限流错误

## 调整
1. 对XTP接口的行情价格数据基于合约最小价格跳动进行取整，资金保留2位小数
2. BaseMonitor保存CSV文件时，表头改为图形界面显示的中文（之前是数据的字段名英文）
3. 初始化TWAP算法时，对每轮委托数量取整到合约最小交易数量
4. 将原vnpy.trader.database中的数据库客户端拆分到独立的vnpy.database模块下
5. 对SQLite/MySQL/PostgreSQL/MongoDB/InfluxDB客户端进行代码重构优化，增加K线数据整体情况BarOverview查询功能

## 新增
1. 新增BaseMonitor数据监控UI组件（以及其子类），自动保存列宽的功能
2. 增加华鑫奇点ToraGateway对于FENS服务器连接和资金账户登录的支持，之前只支持前置机连接和用户代码登录 
3. 增加火币永续合约HuobisGateway对于USDT本位合约的支持
4. 增加InfluxDB数据库客户端vnpy.database.influx对于Tick数据储存和加载的支持