import requests
import re
import datetime
import time
import random

proxies = {
'http' : 'http://127.0.0.1:1080',
'https' : 'https://127.0.0.1:1080'
}
#nl 过期时间
def get_whois(domain):
	try_times = 0
	while try_times < 3:
		try:

			r = requests.get('https://who.is/whois/'+domain)
			time.sleep(random.randint(5,10))
			results = r.text
			whois_info = re.search(r'<pre style="border:0px;">(.*)</pre></div>',results,re.S)
			#print(whois_info)
		except:
			print('sth is wrong.')
			time.sleep(random.randint(3,5))
			try_times += 1
		else:
			if whois_info != None:
				whois_info = whois_info.group(1)
				if 'in quarantine' in whois_info:
					date_quarantine = re.search(r'Date out of quarantine: (.*?)\n', whois_info).group(1)
					date_quarantine = date_quarantine.replace('T',' ')
					date_quarantine = datetime.datetime.strptime(date_quarantine, '%Y-%m-%d %H:%M:%S') + datetime.timedelta(hours=8)
					date_quarantine = date_quarantine.strftime('%Y-%m-%d %H:%M:%S')
					#print('%s 过期时间约为: %s' % (domain, date_quarantine))
					return {domain : date_quarantine}
				else:
					break
			else:
				break

#be 过期时间                   
def whois_dnsbelgium(domain):
	try_times = 0
	url = 'https://api.dnsbelgium.be/whois/registration/' + domain   
    #print(r.status_code)
	while try_times < 3:
		try:
			r = requests.get(url,proxies=None)
			#print(r)
			time.sleep(random.randint(3,5))	
		except:
			print('sth is wrong.')
			try_times += 1
			time.sleep(random.randint(3,5))
		else:
			if r.status_code == 200:
				rj = r.json()['domainInfo']['dateAvailable']
				if rj != None:
					rj = rj.replace(r'T', ' ')
					rj = rj.replace(r'.000Z', '')
					whois_datetime = datetime.datetime.strptime(rj, '%Y-%m-%d %H:%M:%S') + datetime.timedelta(hours=8)
					whois_datetime = whois_datetime.strftime('%Y-%m-%d %H:%M:%S')
					#print(whois_datetime)
					return {domain : whois_datetime}
				else:
					break
			else:
				break

if __name__ == '__main__':
	whois_content = {}
	with open('domains.txt', 'r', encoding='utf-8') as f:
		text = f.read()
	domains = re.findall(r'[a-zA-Z0-9-]+\.[a-zA-Z\.]+', text)	
	for domain in domains:
		domain_whois = get_whois(domain)
		if domain_whois != None:
			whois_content.update(domain_whois)
	print(whois_content)