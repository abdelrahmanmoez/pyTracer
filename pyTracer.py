#!/bin/python

'''
@Author: Abdelrahman Moez (aka Hydra)
@Skype : the_hydr4
@Script: pyTracer.py

'''

import urllib2
import os
from subprocess import Popen, PIPE
import re
import sets
import sys
import socket
from colorama import Fore, Back, init, Style

try:
	from bs4 import BeautifulSoup
except:
	from BeautifulSoup import BeautifulSoup
else:
	sys.exit('You need to install BeautifulSoup module!')

init(autoreset=True)
os.system('clear')
# -------------------------------------------------------
def banner():
	banner = """
****************************************************
* pyTracer version 0.1                             *
* Coded by: Abdelrahman Moez (aka Hydra)           *
* Skype: the_hydr4                                 *
****************************************************
	"""
	print Fore.RED+banner
def GeoIP(IP):
	result = {}
	link = 'http://whatismyipaddress.com/ip/'+IP
	opener = urllib2.build_opener()
	opener.addheaders = [('User-agent', 'Mozilla/5.0')]
	reader = opener.open(link).read()
	soup = BeautifulSoup(reader)
	for tag in soup.findAll('tr'):
		if not tag.find('th').text == 'Blacklist':
			try:
				result [tag.find('th').text.strip(':')] = tag.find('td').text.strip(" ")
			except: 
				pass
	return result
# -------------------------------------------------------
def isIP(user_input):
	ip_formula = re.search(r'\d*\.\d*\.\d*\.\d*', user_input)
	if ip_formula:
		ip = ip_formula.group()
		return True
# -------------------------------------------------------
def trace(IP):
	print '[*] Tracing [',Fore.WHITE+IP,'] ...'
	output = Popen(['traceroute',str(IP)], stdout = PIPE).stdout.read()
	f = open('trace').read()
	print '[*] Finding Locations ... \n'
	IPs = []
	ip_formula = re.findall(r'\d*\.\d*\.\d*\.\d*', f) 
	for ip in ip_formula:
		if ip not in IPs:
			IPs.append(ip)
	
	first_ip = IPs.pop(0)
	IPs.append(first_ip)

	for ip in IPs:
		location = ""
		try:
			result = GeoIP(ip)
			location = ", ".join((result['Country'], result['State/Region'], result['City']))
		except Exception, e: 
			pass
		print Style.BRIGHT+Fore.YELLOW+ip,'\t\t', location
		
	# -------------------------------------------------------
# Check if OS is not linux
if sys.platform.startswith('linux') == False:
	sys.exit("This script needs Linux OS to run!")
# print banner
banner()
# Asking for IP to trace
user_input = raw_input('[>] Enter Host/IP to trace: ')
# Check if input is ip
if isIP(user_input) == True:
	IP = user_input
# And if it was a host, it will try to resolve the IP
else:
	try:
		print '[*] Resolving IP ...'
		IP = socket.gethostbyname(user_input)
	except:
		sys.exit(Style.BRIGHT+Fore.RED+'Can\'t resolve IP!')
# Start tracing
trace(IP)
raw_input('\n$')