#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 适用于Linux环境，Python2.x
import socket
import threadpool
import time
import multiprocessing
import logging

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
logging.basicConfig(filename='scan.log', level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT)
# 扫描(ip, port)，判断端口是否打开
# @param ip
# @param port_number
# @param delay 超时时间，单位s
# @param ports_open 存放打开的端口号
# return None
def tcp_connect(ip, port_number, delay, ports_open):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.settimeout(delay)
    try:
        result = tcp_sock.connect_ex((ip, int(port_number)))
        if result == 0:
            ports_open.append(port_number)
            logging.info('{__ip}:{__port_number}:OPEN'.format(__ip=ip,__port_number=port_number))
        else:
            logging.info('{__ip}:{__port_number}:CLOSE'.format(__ip=ip,__port_number=port_number))
        tcp_sock.close()
    except socket.error as e:
        logging.error('Failed to create socket ')
        pass
    return None

# 对于一个给定的IP地址
# 1、取出一个端口
# 2、新建一条线程，利tcp_connect()函数对该(ip,port)进行连接操作
# 3、使扫描的子线程开始工作并且命令主线程等待子线程死亡后再结束
# 4、重复这个过程直到所有的端口都被扫描过
# @param ip 扫描的主机地址
# @param port_list 扫描的端口列表
# return ports_open 返回打开的端口列表
def sacn_ip_ports(ip, port_list):
    delay = 0.1
    poolsize = 16
    arg_list = list()
    ports_open = list()
    try:
        pool = threadpool.ThreadPool(poolsize)
        for port_number in port_list:
            scan_dic = dict()
            scan_dic['ip'] = ip
            scan_dic['port_number'] = port_number
            scan_dic['delay'] = delay
            scan_dic['ports_open'] = ports_open
            tmp = (None, scan_dic)
            arg_list.append(tmp)
        reqst = threadpool.makeRequests(tcp_connect, arg_list)
        [pool.putRequest(req) for req in reqst]
        pool.wait()
    except:
        logging.error('Thread error')
        pass
    return ports_open

# 多进程扫描，每个进程开启16个线程
# @param ip_list    IP地址范围
# @param port_list  端口范围
# return results    返回扫描结果（端口OPEN）
def multi_ip_port_scan(ip_list, port_list):
    results = dict()
    try:
        pool = multiprocessing.Pool(processes=4)
        for ip in ip_list:
            results[ip] = pool.apply_async(sacn_ip_ports, (ip,port_list)).get()
        pool.close()
        pool.join()
    except:
        logging.error('Process Error')
        pass
    return results

# 展示扫描结果
def show_results(results):
    for ip in results:
        print '='*100
        print 'Server ip is {__ip}'.format(__ip=ip)
        for ports in results[ip]:
            print '[{__port}  OPEN]'.format(__port=ports)

if __name__ == '__main__':
    ip_list = ['127.0.0.1','180.97.33.108','180.97.33.107']
    port_list = range(0,5000)
    print 'Start scanning, please wait patiently....'
    starttime = time.time()
    results = multi_ip_port_scan(ip_list, port_list)
    print 'Scanning completed, consumed %d seconds' % (time.time() - starttime)
    show_results(results)


