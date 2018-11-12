# ddnspod 0.1 by Nukami
# 2018.11.12

from urllib import request, parse
import io
import json
import re
import socket
import threading
import time

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


__record_list = []
__last_ip = ''


class ApiException(Exception):
    def __init__(self, message):
        self.message = message


class RuntimeException(Exception):
    def __init__(self, message):
        self.message = message


def __post(method, data):
    data = parse.urlencode(data).encode('utf-8')
    res = request.urlopen("https://dnsapi.cn/%s" % method, data=data)
    req = res.read().decode("utf-8")
    return json.loads(req)


def __get(url):
    res = request.urlopen(url)
    req = res.read().decode("gbk")
    return req


def __Domain_List():
    data = {
        "login_token": token,
        "format": "json"
    }
    return __post("Domain.List", data)


def __Record_List(domain_id, sub_domain):
    data = {
        "login_token": token,
        "format": "json",
        "domain_id": domain_id,
        "sub_domain": sub_domain,
        "record_type": "A"
    }
    return __post("Record.List", data)


def __Record_Modify(domain_id, sub_domain, record_id, line_id, value):
    data = {
        "login_token": token,
        "format": "json",
        "domain_id": domain_id,
        "sub_domain": sub_domain,
        "record_type": "A",
        "record_id": record_id,
        "value": value,
        "record_line_id": line_id,
        "ttl": ttl
    }
    return __post("Record.Modify", data)


def get_str_time():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def __log(level, method, data):
    if log_level == 'disable':
        return
    elif log_level == 'event' and level != 'event':
        return
    elif log_level == 'error' and level not in ['event', 'error']:
        return

    try:
        text = "[%s][%s][%s]:\n%s\n" % (level, method, get_str_time(), data)
        __flog.writelines(text)
        __flog.flush()
    except:
        pass


def new_record(domain, sub_domain):
    record = {
        "domain": domain,
        "domain_id": '0',
        "sub_domain": sub_domain,
        "records": []
        # {'record_id': '0', 'line_id': '0', 'value': '1.1.1.1'}
    }
    return record


def fix_domain_id(record):
    try:
        domains = __Domain_List()
        __log('debug', 'Domain.List', domains)
        if domains['status']['code'] != '1':
            raise ApiException("Error while getting domains list:%s" % domains['status']['message'])
        domains = domains['domains']
        for tmp in domains:
            if tmp['name'] == record['domain']:
                record['domain_id'] = tmp['id']
                __log('debug', 'domain_id', tmp['id'])
                break
        if record['domain_id'] == '0':
            raise ApiException("Non of domains == matched")
    except ApiException as ae:
        raise ae
    except Exception as e:
        raise RuntimeException("Error while getting domain_id:%s" % e)


def fix_record_id(record):
    try:
        records = __Record_List(record['domain_id'], record['sub_domain'])
        __log('debug', 'Record.List', records)
        if records['status']['code'] != '1':
            raise ApiException("Error while getting records list:%s" % records['status']['message'])
        records = records['records']
        for tmp in records:
            if tmp['name'] == record['sub_domain']:
                sub_record = {'record_id': tmp['id'], 'line_id': tmp['line_id'], 'value': tmp['value']}
                record['records'].append(sub_record)
                __log('debug', 'sub_record', sub_record)
        if len(record['records']) == 0:
            raise ApiException("None of records == matched")
    except ApiException as ae:
        raise ae
    except Exception as e:
        raise RuntimeException("Error while getting record_id:%s" % e)


def get_record(domain, sub_domain):
    record = new_record(domain, sub_domain)
    fix_domain_id(record)
    fix_record_id(record)
    __log('debug', 'new_record', record)
    return record


def append_record(domain, sub_domain):
    try:
        __record_list.append(get_record(domain, sub_domain))
    except ApiException as ae:
        __log('error', 'ApiException', ae)
    except RuntimeException as rte:
        __log('error', 'RuntimeException', rte)


def regenerate_records_list():
    global __record_list
    __log('event', 'regenerate_records_list', 'generating records list...')
    __record_list = []
    for domain in sub_domains.keys():
        for sub_domain in sub_domains[domain]:
            append_record(domain, sub_domain)
    __log('debug', 'regenerate_records_list', __record_list)


def modify_domain_value(domain_id, sub_domain, record_id, line_id, value):
    try:
        res = __Record_Modify(domain_id, sub_domain, record_id, line_id, value)
        __log('debug', 'Record.Modify', res)
        if res['status']['code'] != '1':
            raise ApiException("Error while modifying record value: %s" % res['status']['message'])
    except ApiException as ae:
        __log('error', 'ApiException', ae)
    except Exception as e:
        __log('error', 'RuntimeException', "Error while modifying record value: %s" % e)


def modify_values(value):
    for sub_domain in __record_list:
        for record in sub_domain['records']:
            tmp = (sub_domain['sub_domain'], sub_domain['domain'], record['value'], record['record_id'],
                   record['line_id'])
            if record['value'] == value:
                __log('event', 'modify_value', 'The value of %s.%s is already %s, record_id = %s, line_id = %s' % tmp)
            else:
                __log('event', 'modify_value', 'modifying %s.%s, %s, record_id = %s, line_id = %s' % tmp)
                modify_domain_value(sub_domain['domain_id'], sub_domain['sub_domain'], record['record_id'],
                                    record['line_id'], value)


def get_ip():
    try:
        tmp = __get("http://2018.ip138.com/ic.asp")
        __log('debug', 'get_ip', tmp)
        tmp = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", tmp)
        return tmp.group()
    except Exception as e:
        raise RuntimeException("Error while getting current ip address: %s" % e)


def get_dnspod_ip():
    try:
        sock = socket.create_connection(('ns1.dnspod.net', 6666), timeout=5)
        ip = sock.recv(32).decode('ascii')
        __log('debug', 'get_ip_dnspod', ip)
        return ip
    except Exception as e:
        raise RuntimeException("Error while getting current ip address: %s" % e)


def run():
    global __last_ip
    try:
        ip = get_dnspod_ip()
        __log('debug', 'get_ip', 'Current ip address: %s' % ip)
        if __last_ip != ip:
            __log('event', 'deamon', 'IP address has been changed to %s' % ip)
            regenerate_records_list()
            modify_values(ip)
            __last_ip = ip
    except Exception as e:
        __log('error', 'RuntimeException', "Error while checking ip address: %s" % e)
    next_timer = threading.Timer(interval, run)
    next_timer.start()


if __name__ == "__main__":
    if log_level != 'disable':
        __flog = io.open(log, 'a+')
    first_timer = threading.Timer(1, run)
    first_timer.start()
