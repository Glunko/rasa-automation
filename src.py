from datetime import datetime
import gzip
import sys
from bs4 import BeautifulSoup
import json
import os
import time
import execjs
import urllib3
import urllib.parse
import re
import httplib2
from urllib.parse import unquote
# 忽略ssl证书验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# 持续化会话控制csrfmiddlewaretoken的存活
class CsrfManager:
    def __init__(self):
        self.http = httplib2.Http(".cache")
        self.http.disable_ssl_certificate_validation = True
        self.csrf_token = None
        '''
        #burpsuite测试
        proxy_host = '127.0.0.1'
        proxy_port = '8080'
        proxy_info = httplib2.ProxyInfo(httplib2.socks.PROXY_TYPE_HTTP, proxy_host, int(proxy_port))
        # 将代理信息设置到Http对象中
        self.http.proxy_info = proxy_info'''
#获取未登录的csrfmiddlewaretoken和cookie
    def get_csrf_token(self, url):
        response, content = self.http.request(url, 'GET')
        soup = BeautifulSoup(content, 'html.parser')
        csrf_input = soup.find('input', attrs={'name': 'csrfmiddlewaretoken'})
        if csrf_input:
            self.csrf_token = csrf_input['value']
        cookie_header = response.get('set-cookie', '')
        cookies = {}
        for cookie in cookie_header.split(','):
            cookie_parts = cookie.strip().split(';')
            for part in cookie_parts:
                if '=' in part:
                    key, value = part.strip().split('=', 1)
                    cookies[key] = value
        cookie_data = "csrftoken=" + cookies.get('csrftoken') + "; sessionid=" + cookies.get('sessionid')
        return self.csrf_token,cookie_data
csrf_manager = CsrfManager()
userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

header = {
        'User-Agent': userAgent,
        'Connection':'keep-alive'
    }
login_url = "https://your_rsas_ipadress/accounts/login_view/" 

def gsmLogin():  
    csrf,cookies0 = csrf_manager.get_csrf_token('https://your_rsas_ipadress/accounts/login_view/')
    header1 = {
        'Host': 'your_rsas_ipadress',
        'User-Agent': userAgent,
        'Connection':'keep-alive',
        'Cookie': cookies0,
        'Cache-Control': 'max-age=0',
        'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'https://your_rsas_ipadress',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Referer': 'https://your_rsas_ipadress/accounts/login/?next=/',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6'
    }
    #print(cookies0)
    print("开始模拟登录")
    # 配置账号密码
    account=''
    passwd = ''
    #密码aes加密
    with open('aes.js', 'r', encoding='UTF-8') as f:
        js_code = f.read()
    context = execjs.compile(js_code)
    password = context.call("Encrypt",passwd)
    postData = urllib.parse.urlencode({
    "username": account,
    "password": password,   
    "csrfmiddlewaretoken": csrf
    }).encode('utf-8')
    # 传参登录
    responseRes1,content1= csrf_manager.http.request(login_url, 'POST',body = postData, headers = header1)
    # 是否登陆成功 statusCode = 302(绿盟登录设置了302重定向)
    status_code = responseRes1['status']
    print(f"status code = {status_code}")
    if status_code == '302':
        print('登陆成功')
    else :
        print('登陆失败')
    # 获取登陆后的cookie
    cookie_header2 = responseRes1.get('set-cookie', '')
    cookies_logined = {}
    for cook1e in cookie_header2.split(','):
        cookie_parts = cook1e.strip().split(';')
        for part in cookie_parts:
            if '=' in part:
                key, value = part.strip().split('=', 1)
                cookies_logined[key] = value
    cookie_data2 = "csrftoken=" + cookies_logined.get('csrftoken') + "; sessionid=" + cookies_logined.get('sessionid')
    return cookie_data2
# 获取登陆后的csrfmiddlewaretoken值
def get_logined_csrfmiddlewaretoken():
    cookie_logined = gsmLogin()
    header1 = {
            'User-Agent': userAgent,
            'Connection':'keep-alive',
            'cookie':cookie_logined
        }
    getlogined_url = "https://your_rsas_ipadress/task/index/8"
# 还是通过csrf_manager.http.request让csrfmiddlewaretoken存活
    responseRes2,content2= csrf_manager.http.request(getlogined_url, 'GET', headers = header1)
    soup = BeautifulSoup(content2, 'html.parser')
    csrf_input = soup.find('input', attrs={'name': 'csrfmiddlewaretoken'})
    if csrf_input:
        csrf_token = csrf_input['value']
        return cookie_logined,csrf_token
def checkurl():
    with open('1.txt', 'r', encoding='utf-8') as file:
        lines = file.readlines()
    cookie_logined,csrf_token= get_logined_csrfmiddlewaretoken()

    # 提取任务名字和URL列表
    task_name = ''
    urls = []
    protocalarray = []
    for line in lines:
        line = line.strip()
        if re.search('[\u4e00-\u9fff]', line):  # 检测是否包含中文字符
            if not line.startswith("运行时间"):
                task_name = line
            else:
                pattern = r"运行时间：([^：\n]*)"
                match = re.search(pattern, line)
                exectime = match.group(1).strip()
        else:
            url = line.strip()  # 去除行尾的换行符和空格
            target = {
                "target": url,
                "protocal_type": "auto",
                "protocal_name": "",
                "protocal_pwd": "",
                "login_scan_type": "no",
                "cookies": "",
                "cookie_type": "set_cookie",
                "black_links": "",
                "wihte_links": "",
                "form_switch": "no",
                "form_cont": "no",
                "form_str": ""
            }
            protocalarray.append(target)  # 将目标值添加到列表中
            urls.append(line)
    protocalarray = json.dumps(protocalarray, ensure_ascii=False)
    if exectime == "现在":
        exetime = "immediate"
        # 获取当前时间
        exectime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    else :
        exetime = "timing"
    #正则匹配时间格式
    time_check = r"\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}$"
    time_match = re.match(time_check, exectime)
    if time_match:
        print("时间格式正确，运行时间为:" + exectime)
    else :
        print("时间格式错误啦！")
    print("任务名称为：" + task_name)
    checkurl = "https://your_rsas_ipadress/task/web_validate_targets/"
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
    headers = {
            "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
            "Accept": "application/json, text/javascript, */*",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Sec-Ch-Ua-Mobile": "?0",
            "User-Agent": userAgent,
            "Sec-Ch-Ua-Platform": "\"Windows\"",
            "Origin": "https://your_rsas_ipadress",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://your_rsas_ipadress/task/index/8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6",
            'cookie':cookie_logined
                
        }
    data = urllib.parse.urlencode({
        'csrfmiddlewaretoken': csrf_token,
        'target_count': str(len(urls)),
        'config_task': 'taskname',
        'task_config': '',
        'task_target': ' '.join(urls),  
        'task_name': task_name, 
        'scan_method': '1',
        'subdomains_scan': '0',
        'subdomains': '',
        'exec': 'immediate',
        'exec_timing_date': '',
        'exec_everyday_time': '00:00',
        'exec_everyweek_day': '1',
        'exec_everyweek_time': '00:00',
        'exec_emonthdate_day': '1',
        'exec_emonthdate_time': '00:00',
        'exec_emonthweek_pre': '1',
        'exec_emonthweek_day': '1',
        'exec_emonthweek_time': '00:00',
        'tpl': '0',
        'ws_proxy_type': 'HTTP',
        'ws_proxy_auth': 'Basic',
        'ws_proxy_server': '',
        'ws_proxy_port': '',
        'ws_proxy_username': '',
        'ws_proxy_password': '',
        'cron_range': '',
        'dispatchLevel': '2',
        'target_description': '',
        'report_type_html': 'html',
        'summarizeReport': 'yes',
        'oneSiteReport': 'yes',
        'sum_report_tpl': '201',
        'site_report_tpl': '301',
        'sendReport_type': 'html',
        'email_address': '',
        'scan_level': '2',
        'plugin_threads': '10',
        'webscan_timeout': '30',
        'page_encoding': '0',
        'coding': 'UTF8',
        'login_ifuse': 'yes',
        'user_agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN; rv:1.9.2.4) Gecko/20100611 Firefox/3.6.4',
        'header_count': '0',
        'header_key': '',
        'header_value': '',
        'dir_level': '1',
        'dir_limit': '3',
        'filetype_to_check_backup': 'shtml,php,jsp,asp,aspx',
        'backup_filetype': 'bak,old',
        'text2': '',
        #绿盟弱密码检测在post信息里
        'weak_count': '11',
        'weak_user': '',
        'weak_pwd': '',
        'weak_user_11': 'Administrator',
        'weak_pwd_11': 'Administrator',
        'weak_user_10': 'test',
        'weak_pwd_10': 'abc123',
        'weak_user_9': 'test',
        'weak_pwd_9': '123456',
        'weak_user_8': 'root',
        'weak_pwd_8': '',
        'weak_user_7': 'root',
        'weak_pwd_7': '123456',
        'weak_user_6': 'test',
        'weak_pwd_6': 'test',
        'weak_user_5': 'root',
        'weak_pwd_5': 'root',
        'weak_user_4': 'admin',
        'weak_pwd_4': 'abc123',
        'weak_user_3': 'admin',
        'weak_pwd_3': 'admin888',
        'weak_user_2': 'admin',
        'weak_pwd_2': '123456',
        'weak_user_1': 'admin',
        'weak_pwd_1': 'admin',
        'scan_type': '0',
        'dir_files_limit': '30',
        'dir_depth_limit': '15',
        'scan_link_limit': '10000',
        'file_exts': 'png, gif, jpg, mp4, mp3, mng, pct, bmp, jpeg, pst, psp, ttf, tif, tiff, ai, drw, wma, ogg, wav, ra, aac, mid, au, aiff, dxf, eps, ps, svg, 3gp, asf, asx, avi, mov, mpg, qt, rm, wmv, m4a, bin, xls, xlsx, ppt, pptx, doc, docx, odt, ods, odg, odp, exe, zip, rar, tar, gz, iso, rss, pdf, txt, dll, ico, gz2, apk, crt, woff, map, woff2, webp, less, dmg, bz2, otf, swf, flv, mpeg, dat, xsl, csv, cab, exif, wps, m4v, rmvb, msi, deb, rpm, terrain',
        'case_sensitive': '1',
        'if_javascript': '1',
        'if_repeat': '2',
        'max_page_concurrent': '5',
    }).encode('utf-8')
    responseRes3,content3= csrf_manager.http.request(checkurl, 'POST',body = data, headers = headers)
    response_data = json.loads(content3)
    status = response_data.get('status')
    msg = response_data.get('msg')

    if status == 'success':
        flag = True
        count = response_data.get('count')
        print('格式正确，地址为'+ str(urls))
        print('目标个数:', count)
    elif status == 'fail':
        flag = False
        print('格式错误，请检查地址格式')
        print(msg)
    else:
        print('出错啦')
        flag = False
    checkurl_able = "https://your_rsas_ipadress/task/web_is_reachable/"
    if flag:
        responseRes3_1,content3_1= csrf_manager.http.request(checkurl_able, 'POST',body = data, headers = headers)
        if content3_1 == b'true':
            print('站点存在')
            flag = True
        else:
            print('站点不存在')
            flag = False
    if flag:
        header1 = {
            'User-Agent': userAgent,
            'Connection':'keep-alive',
            'cookie':cookie_logined
        }
        header2 = {
            'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'Accept': 'application/json, text/javascript, */*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest',
            'Sec-Ch-Ua-Mobile': '?0',
            'User-Agent': userAgent,
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Origin': 'https://your_rsas_ipadress',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://your_rsas_ipadress/system/tools/list/curl/',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6',
            'cookie': cookie_logined
        }
        getcurl_url_csrf = "https://your_rsas_ipadress/system/tools/list/curl/"
        curl_url = "https://your_rsas_ipadress/system/tools/execute/Curl"
        get_result_url = "https://your_rsas_ipadress/system/tools/flush/Curl"
        responseRes4,content4= csrf_manager.http.request(getcurl_url_csrf, 'GET', headers = header1)
        soup = BeautifulSoup(content4, 'html.parser')
        csrf_input = soup.find('input', attrs={'name': 'csrfmiddlewaretoken'})
        if csrf_input:
            csrf_token = csrf_input['value']
        print("下面是curl结果：")
        for url in urls:        
            body = 'cmd={}&csrfmiddlewaretoken={}'.format(url, csrf_token)
            csrf_manager.http.request(curl_url, 'POST',body = body, headers = header2)
            body2 = 'csrfmiddlewaretoken={}'.format(csrf_token)
            time.sleep(2)
            result = True
            while result:
                responseRes_check_result,content_check_result = csrf_manager.http.request(get_result_url, 'POST',body = body2, headers = header2)
                content_data = json.loads(content_check_result)
                #持续发包检查curl是否完成
                if content_data.get('status') == "done":
                    result = False
                elif content_data.get('status') == "running":
                    continue
                print('')
                print("\033[1;37;46m{} \033[0m".format(url))
                print(content_check_result.decode('utf-8'))
                match = re.search("连接超时", content_check_result.decode('utf-8'))
                if match:
                    print("连接超时请问是否需要继续添加扫描（可能会扫描异常，定时任务可添加）")
                    continue1 = input("请输入y继续添加任务,n为停止:\n")
                    if  continue1 == "y":
                        break
                    elif continue1 == "n":
                        os._exit(1)
    return cookie_logined,csrf_token,task_name,urls,exectime,exetime,protocalarray

def senturl():
    cookie_logined,csrf_token,task_name,urls,exectime,exetime,protocalarray= checkurl()
    senturl = "https://your_rsas_ipadress/task/web_newtask/"
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
    headers = {
            "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
            "Accept": "application/json, text/javascript, */*",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Sec-Ch-Ua-Mobile": "?0",
            "User-Agent": userAgent,
            "Sec-Ch-Ua-Platform": "\"Windows\"",
            "Origin": "https://your_rsas_ipadress",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://your_rsas_ipadress/task/index/8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6",
            'cookie':cookie_logined
                
        }
    data = urllib.parse.urlencode({
        'csrfmiddlewaretoken': csrf_token,
        'target_count': str(len(urls)),
        'config_task': 'taskname',
        'task_config': '',
        'task_target': ' '.join(urls),  
        'task_name': task_name, 
        'scan_method': '1',
        'subdomains_scan': '0',
        'subdomains': '',
        'exec': exetime,
        'exec_timing_date': exectime,
        'exec_everyday_time': '00:00',
        'exec_everyweek_day': '1',
        'exec_everyweek_time': '00:00',
        'exec_emonthdate_day': '1',
        'exec_emonthdate_time': '00:00',
        'exec_emonthweek_pre': '1',
        'exec_emonthweek_day': '1',
        'exec_emonthweek_time': '00:00',
        'tpl': '0',
        'ws_proxy_type': 'HTTP',
        'ws_proxy_auth': 'Basic',
        'ws_proxy_server': '',
        'ws_proxy_port': '',
        'ws_proxy_username': '',
        'ws_proxy_password': '',
        'cron_range': '',
        'dispatchLevel': '2',
        'target_description': '',
        'report_type_html': 'html',
        'summarizeReport': 'yes',
        'oneSiteReport': 'yes',
        'sum_report_tpl': '201',
        'site_report_tpl': '301',
        'sendReport_type': 'html',
        'email_address': '',
        'scan_level': '2',
        'plugin_threads': '10',
        'webscan_timeout': '30',
        'page_encoding': '0',
        'coding': 'UTF8',
        'login_ifuse': 'yes',
        'user_agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN; rv:1.9.2.4) Gecko/20100611 Firefox/3.6.4',
        'header_count': '0',
        'header_key': '',
        'header_value': '',
        'dir_level': '1',
        'dir_limit': '3',
        'filetype_to_check_backup': 'shtml,php,jsp,asp,aspx',
        'backup_filetype': 'bak,old',
        'text2': '',
        'weak_count': '11',
        'weak_user': '',
        'weak_pwd': '',
        'weak_user_11': 'Administrator',
        'weak_pwd_11': 'Administrator',
        'weak_user_10': 'test',
        'weak_pwd_10': 'abc123',
        'weak_user_9': 'test',
        'weak_pwd_9': '123456',
        'weak_user_8': 'root',
        'weak_pwd_8': '',
        'weak_user_7': 'root',
        'weak_pwd_7': '123456',
        'weak_user_6': 'test',
        'weak_pwd_6': 'test',
        'weak_user_5': 'root',
        'weak_pwd_5': 'root',
        'weak_user_4': 'admin',
        'weak_pwd_4': 'abc123',
        'weak_user_3': 'admin',
        'weak_pwd_3': 'admin888',
        'weak_user_2': 'admin',
        'weak_pwd_2': '123456',
        'weak_user_1': 'admin',
        'weak_pwd_1': 'admin',
        'scan_type': '0',
        'dir_files_limit': '30',
        'dir_depth_limit': '15',
        'scan_link_limit': '10000',
        'file_exts': 'png, gif, jpg, mp4, mp3, mng, pct, bmp, jpeg, pst, psp, ttf, tif, tiff, ai, drw, wma, ogg, wav, ra, aac, mid, au, aiff, dxf, eps, ps, svg, 3gp, asf, asx, avi, mov, mpg, qt, rm, wmv, m4a, bin, xls, xlsx, ppt, pptx, doc, docx, odt, ods, odg, odp, exe, zip, rar, tar, gz, iso, rss, pdf, txt, dll, ico, gz2, apk, crt, woff, map, woff2, webp, less, dmg, bz2, otf, swf, flv, mpeg, dat, xsl, csv, cab, exif, wps, m4v, rmvb, msi, deb, rpm, terrain',
        'case_sensitive': '1',
        'if_javascript': '1',
        'if_repeat': '2',
        'max_page_concurrent': '5',
        'protocalarray': protocalarray
    }).encode('utf-8')
    responseRes5,content5= csrf_manager.http.request(senturl, 'POST',body = data, headers = headers)
    response_data = content5.decode('utf-8')
    result = re.search(r":([^:]+):([^:]+)", response_data)
    flag = True
    if flag:
        result2 = result.group(1)
        if result2 == "suc":
            num = result.group(2)
            print("创建任务成功！")
            print("任务序号为:", num)
        elif result2 == "err":
            print("创建任务失败")
        flag = False
    else:
        pass
def getlist():
    #获取X-token
    cookie_logined,csrf_token = get_logined_csrfmiddlewaretoken()
    cookie_pairs = cookie_logined.split(";")
    for pair in cookie_pairs:
        key, value = pair.strip().split("=")
        if key == "csrftoken":
            csrftoken = value
            break

    getlist_url = 'https://your_rsas_ipadress/list/getList'
    headers = {
    'Cookie': cookie_logined,
    'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
    'Sec-Ch-Ua-Mobile': '?0',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Accept': '*/*',
    'X-Requested-With': 'XMLHttpRequest',
    'X-Csrftoken': csrftoken,
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Origin': 'https://your_rsas_ipadress',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Referer': 'https://your_rsas_ipadress/list/',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6',
    'Connection': 'close'
    }
    headers2 = {
    'Cookie': cookie_logined,
    'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
    'Sec-Ch-Ua-Mobile': '?0',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'X-Requested-With': 'XMLHttpRequest',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Origin': 'https://your_rsas_ipadress',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Referer': 'https://your_rsas_ipadress/list/',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6',
    'Connection': 'close'
    }
    
    data = 'csrfmiddlewaretoken={}&ip=&task_name=&domain=&task_status=&rs_template=&tpl=&protect_level=S1A1G1&account=&time_start_scan=&time_end_scan=&task_type=8&page=1&page_count=25&exp_task=undefined&bvs_template=&protect_level='.format(csrf_token)
    responseRes6,content6= csrf_manager.http.request(getlist_url, 'POST',body = data, headers = headers)
    sys.stdout.flush()
    content6 = content6.decode('utf-8')
    soup = BeautifulSoup(content6, 'html.parser')
    td_elements = soup.find_all('td')
    a_elements = soup.select('a[id*=name]')
    td_texts = []  
#定位td
    for td in td_elements:
        span_progress = td.find('span', class_='cmn_progress')
        if span_progress:
            td_text = td.get_text(strip=True)
            td_texts.append(td_text)
#zip()同时输出  
    for a_element, td in zip(a_elements, td_texts):
        id_value = a_element['id']
        title = a_element['title']
        color = a_element['style']
        name_id = re.findall(r'\d+', id_value)[0]
        print("任务名:", title)
        print("任务id:", name_id)
        start_time_id = re.findall(r'\d+', id_value)[0]
        start_time_element = soup.select_one(f"td div[id*=starttime{start_time_id}]")
        end_time_element = soup.select_one(f"td div[id*=endtime{start_time_id}]")
        if start_time_element and end_time_element:
            start_time = start_time_element.text.strip()
            end_time = end_time_element.text.strip()
            print("开始时间:", start_time)
            print("结束时间:", end_time)
            flag3 = True
            #灰色的扫描任务进度为100%是扫描异常的项目
            if color == "cursor:pointer;color:#7A7A7A;" and td == "100%":
                td = "扫描异常"
                getworng_url = 'https://your_rsas_ipadress/report/summary/taskid/{}'.format(name_id)
                responseRes7,content7= csrf_manager.http.request(getworng_url, 'GET', headers = headers2)
                content7 = content7.decode('utf-8')
                soup2 = BeautifulSoup(content7, 'html.parser')
                tr_tags = soup2.find_all('tr')
                flag3 = False
                print("\033[1;37;41m进度:{} \033[0m".format(td))
                #记录扫描异常的站点
                for tr_tag in tr_tags:
                    th_tag = tr_tag.find('th')
                    if th_tag and th_tag.text.strip() == '异常站点':
                        #正则去掉空行
                        text = re.sub(r'\s+', ' ', tr_tag.text.strip())
                        if text:
                            print("\033[1;37;41m进度:{} \033[0m".format(text))
                            time.sleep(2)
            else:
                pass   
            if flag3 :
                print("\033[1;37;46m进度:{} \033[0m".format(td))
        print()

def downloadfile():
    cookie_logined,csrf_token = get_logined_csrfmiddlewaretoken()
    flag = True
    while flag:
        id = input("请输入你需要输出的任务id：\n")
        # 这里判断任务id为3位数到4位数，不需要可以删掉
        if id.isdigit() and 3 <= len(id) <= 4:
            flag = False
        else:
            print("输入错误")
    #发送输出报告请求
    report_url = 'https://your_rsas_ipadress/report/export'
    headers = {
        'Cookie': cookie_logined,
        'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
        'Accept': '*/*',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest',
        'Sec-Ch-Ua-Mobile': '?0',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Origin': 'https://your_rsas_ipadress',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://your_rsas_ipadress/report/',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6',
        'Connection': 'close'
    }

    data = urllib.parse.urlencode({
        'export_area': 'web',
    #默认输出html，doc，xls三个漏洞报告
        'report_type': ['html', 'doc', 'xls'],
        'report_content': ['websummary', 'site'],
        'summary_template_id': '201',
        'summary_report_title': '综合科技"远程安全评估系统"安全评估报告',
        'host_template_id': '301',
        'single_report_title': '综合科技"远程安全评估系统"安全评估报告-站点报表',
        'multi_export_type': 'multi_sum',
        'multi_report_name': '多任务输出',
        'csrfmiddlewaretoken': csrf_token,
        'from': 'report_export',
        'task_id': id
        #doseq取消覆盖变量，同时发送相同的变量到post包
    }, doseq=True).encode('utf-8')
    responseRes8,content8= csrf_manager.http.request(report_url, 'POST',body = data, headers = headers)
    content8 = content8.decode('utf-8')
    # 去除括号
    content8 = content8[1:-1]
    response_data = json.loads(content8)
    result = response_data['result']
    report_id = response_data['context']['report_id']
    if result == 'success':
        print("创建任务报告成功，任务报告号为:", report_id)
        print("正在导出...")
        #确认是否输出报告完成
        flag2 = True
        while flag2:
            check_report_url = 'https://your_rsas_ipadress/report/export/process/id/{}'.format(report_id)
            headers2 = {
                'Cookie': cookie_logined,
                'Cache-Control': 'max-age=0',
                'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Dest': 'iframe',
                'Referer': 'https://your_rsas_ipadress/report/export/process/id/{}'.format(report_id),
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6',
                'Connection': 'close'
            }
            
            responseRes9,content9= csrf_manager.http.request(check_report_url, 'GET', headers = headers2)
            content9 = content9.decode('utf-8')
            soup = BeautifulSoup(content9, 'html.parser')
            img_tag = soup.find('img', class_='ico')
            if img_tag:
                text = img_tag.next_sibling.strip() 
                print(text)
                flag2 = False
            elif img_tag == None:
                time.sleep(2)
    elif result == 'error':
        print("输出任务报告失败，请检查任务是否扫描完成")
    if flag2 ==  False:
        if not os.path.exists("download"):
            os.makedirs("download")
        headers3 = {
            'Cookie': cookie_logined,
            'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'iframe',
            'Referer': 'https://your_rsas_ipadress/report/list/',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6',
            'Connection': 'close'
        }
        Files = ['html','xls','doc']
        for file1 in Files: 
            getfile_url = 'https://your_rsas_ipadress/report/download/id/{}/type/{}'.format(report_id,file1)
            responseRes_file,content_file= csrf_manager.http.request(getfile_url, 'GET', headers = headers3)
            if responseRes_file.status == 200:
                # 获取 Content-Disposition 头字段的值
                content_disposition = responseRes_file.get("content-disposition", "")
                # 提取文件名
                filename = ""
                if content_disposition:
                    _, params = content_disposition.split(";")
                    for param in params.split(";"):
                        key, value = param.strip().split("=")
                        if key.strip().lower() == "filename":
                            filename = unquote(value.strip().strip('"'))
                            filename = filename.encode('ISO-8859-1').decode('gbk')
                if not filename:
                    # 如果无法从 Content-Disposition 获取文件名，则使用 URL 中的文件名(编码不对会乱码)
                    filename = os.path.basename(getfile_url)
                file_path = os.path.join("download", filename.replace("/", "\\")) 
                # 将内容保存到文件
                with open(file_path, "wb") as file:
                    file.write(content_file)
                print("{}文件下载成功！保存路径：{}".format(file1,file_path))
            else:
                print("文件下载失败！")
def stop_task():
    cookie_logined,csrf_token = get_logined_csrfmiddlewaretoken()
    stop_url = 'https://your_rsas_ipadress/list/stopTask/'
    taskid = input("请输入你要停止的任务号：\n")
    headers = {
    'Cookie': cookie_logined,
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
    'Referer': 'https://your_rsas_ipadress/list/'
    }
    body = 'csrfmiddlewaretoken={}&ip=&task_name=&domain=&task_status=&rs_template=&tpl=&protect_level=S1A1G1&account=&time_start_scan=&time_end_scan=&op=stop&id={}&task_type=&page=1&page_count=25'.format(csrf_token,taskid)
    stop_response, stop_content = csrf_manager.http.request(stop_url, method='POST', headers=headers, body=body)
    if stop_response.status == 200:
        html = stop_content.decode('utf-8')
        soup = BeautifulSoup(html, 'html.parser')
        script_tags = soup.find_all('script', type='text/javascript')
        pattern = r"alert\('([^']*)'\)"
        for script_tag in script_tags:
            text = script_tag.string
            if text and 'alert' in text:
                matches = re.findall(pattern, text)
                for match in matches:
                    print(match)
    else:
        print("请检查任务号是否正确")
def delete_task():
    cookie_logined,csrf_token = get_logined_csrfmiddlewaretoken()
    del_url = 'https://your_rsas_ipadress/list/delTask/'
    taskid = input("请输入你要删除的任务号：\n")
    get_msg_url = 'https://your_rsas_ipadress/report/summary/taskid/{}/'.format(taskid)
    header = {
        'Cookie': cookie_logined,
        'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'iframe',
        'Referer': 'https://your_rsas_ipadress/list/',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6',
        'Connection': 'close'
    }
    headers = {
    'Cookie': cookie_logined,
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
    'Referer': 'https://your_rsas_ipadress/list/'
    }
    body = 'csrfmiddlewaretoken={}&ip=&task_name=&domain=&task_status=&rs_template=&tpl=&protect_level=S1A1G1&account=&time_start_scan=&time_end_scan=&op=del&id={}&task_type=&page=1&page_count=25'.format(csrf_token,taskid)
    msg_response,msg_content= csrf_manager.http.request(get_msg_url, 'GET', headers = header)
    msg_content = msg_content.decode('utf-8')
    soup = BeautifulSoup(msg_content, 'html.parser')
    title = soup.title.string
    if title != "任务不存在":
        print("请确认任务是否删除：")
        tr_tags = soup.select('tr[class="odd"]')
        for tr_tag in tr_tags:
            th_tag = tr_tag.find('th', text='任务名称')
            if th_tag:
                td_tag = th_tag.find_next_sibling('td')
                if td_tag:
                    text = td_tag.get_text(strip=True)
                    print(text)
        qr = input("输入y确认删除，n退出：")
        if qr == "y":
            del_response, del_content = csrf_manager.http.request(del_url, method='POST', headers=headers, body=body)
            if del_response.status == 200:
                html = del_content.decode('utf-8')
                soup = BeautifulSoup(html, 'html.parser')
                script_tags = soup.find_all('script', type='text/javascript')
                pattern = r"alert\('([^']*)'\)"
                for script_tag in script_tags:
                    text = script_tag.string
                    #匹配任务删除成功
                    if text and 'alert' in text:
                        matches = re.findall(pattern, text)
                        for match in matches:
                            print(match)
                            print()
            else:
                print("请检查任务号是否正确")
        elif qr == "n":
            pass
        else:
            print("请检查输入")
    elif title == "任务不存在":
        print('请检查任务是否存在')

if __name__ == "__main__":
    while True:
        print()
        print("欢迎使用扫描器，本脚本只支持web扫描")
        print("1. 生成任务（请先检查txt是否配置）")
        print("2. 检查url存活")
        print("3. 获取当前web扫描列表")
        print("4. 下载报表")
        print("5. 停止任务")
        print("6. 删除任务")
        print("0. 退出")

        choice = input("请输入选项：")

        if choice == "1":
            senturl()
        elif choice == "2":
            checkurl()
        elif choice == "3":
            getlist()
        elif choice == "4":
            downloadfile()
        elif choice == "5":
            stop_task()
        elif choice == "6":
            delete_task()
        elif choice == "0":
            print("谢谢使用，再见！")
            break
        else:
            print("输入错误，请重新输入！")
