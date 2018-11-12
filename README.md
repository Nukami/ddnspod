# ddnspod
  + 定时检查IP变更
  + 更新DNSPOD记录
  + 基于DNSPOD提供的API实现
  + 支持多域名
  + Nukami / 2018.11.12

# 环境需求
+ python3
+ 运行于需要ddns的网络内

# DNSPOD参数
  DNSPOD参数包括 token, sub_domains, ttl, 均为必选参数。
### 1. Token
  token为DNSPOD的鉴权token，可以参考 [如何使用 Token 来调用 API]( https://support.dnspod.cn/Kb/showarticle/tsid/227/)
### 2. Subdomains
  sub_domains 指定了用于ddns的域名与对应的子域名, 支持多个域名及多个子域名, 被指定的域名必须已经存在于DNSPOD记录中, 否则无法更新  
  请按照以下格式指定子域名:  
  ```sub_domains = {'example.com': ['www', 'blog'], 'example.org': ['www']}```
### 3. TTL
  TTL, 生存时间指定了一条记录在DNS服务器上的缓存时间, DNSPOD免费版最低限制为600秒

# 脚本参数
  脚本参数包括 interval, log, log_level。
### 1. Interval
  interval 值指定了两次IP检测之间的间隔，单位为秒，数值越小对IP变更的响应越及时。
### 2. Log level
  log_level 的值对应的日志详细程度, 由大到小可为 debug > error > event, 当 log_level 为 disable 时, 日志不可用
### 3. Log path
  log 参数指定了日志文件存放的路径, 当 log_level 为 disable 时, 该参数无效
  
# 示例
  一个linux上的单子域名ddns配置如下:
```
# To generate an API Token, please follow the official token guide by DNSPOD:
# https://support.dnspod.cn/Kb/showarticle/tsid/227/ ;
# sub_domains setup a list of subdomains for those you need to modify, it should looks like:
# {'example.com': ['www', 'blog'], 'example.org': ['www']} ;
# ttl(Time to live) value indicates the expired time of record cache on dns server,
# for more details, please visit:
# https://en.wikipedia.org/wiki/Time_to_live#DNS_records
# ! NOTE that the minimal ttl for free user on dnspod is limited to 600
token = "72604,f26d62a1b0b7a73fe667cab5b3ca52ad"
sub_domains = {'sailark.com': ['srv1']}
ttl = 600

# interval value is the time interval between an ip check to the next ip check ;
# Use log value to specify log path ;
# To disable log, or specify log level, please use log_level value
# log_level in ['debug', 'error', 'event', 'disable']
interval = 5
log = "/var/log/ddnspod"
log_level = 'event'
```

# 开机启动
若需要将位于/scripts/ddnspod.py的脚本设置为在开机后启动, 只需要遵从以下步骤:
+ 编辑/etc/rc.d/rc.local, 在 exit 0前插入
```
python3 /scripts/ddnspod.py
```
+ 为rc.local赋予执行权限
```
chmod +x /etc/rc.d/rc.local
```
+ 重启系统