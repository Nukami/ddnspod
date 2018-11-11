from urllib import request, parse
import io
import json
import re
import time

# https://support.dnspod.cn/Kb/showarticle/tsid/227/
# To generate an API Token, please follow the official token guide by dnspod.cn
token = "72604,f26d62a1b0b7a73fe667cab5b3ca52ad"
sub_domains = {'sailark.com': ['srv1']}
ttl = 600

alternation = 10
log = "ddnspod"
# log_level in ['debug', 'error', 'event', 'disable']
log_level = 'debug'

__record_list = []
__flog = None
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
        # {'record_id': '0', 'line_id': '0'}
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
                sub_record = {'record_id': tmp['id'], 'line_id': tmp['line_id']}
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
    __log('event', 'regenerate_records_list', 'generating records list...')
    __record_list.clear()
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
            tmp = (sub_domain['sub_domain'], sub_domain['domain'], record['record_id'], record['line_id'])
            __log('event', 'modify_value', 'modifying %s.%s, record_id = %s, line_id = %s' % tmp)
            modify_domain_value(sub_domain['domain_id'], sub_domain['sub_domain'], record['record_id'],
                                record['line_id'], value)


def get_ip():
    try:
        tmp = __get("http://2018.ip138.com/ic.asp")
        tmp = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", tmp)
        return tmp.group()
    except Exception as e:
        raise RuntimeException("Error while getting current ip address: %s" % e)


def run():
    try:
        ip = get_ip()
        __log('debug', 'get_ip', 'Current ip address: %s' % ip)
        if __last_ip != ip:
            __log('event', 'modify_values', 'IP address has been changed')
            modify_values(ip)
    except Exception as e:
        __log('error', 'RuntimeException', "Error while checking ip address: %s" % e)


if __name__ == "__main__":
    __flog = io.open(log, 'w+')
    regenerate_records_list()
    run()
    # print(__record_list)
    # print(__Record_Modify(68861243, sub_domains[0], "384445664", "0", "219.128.20.237"))
