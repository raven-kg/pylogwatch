# -*- coding: utf-8 -*-
from pylogwatch.formatters.base import BaseFormatter
from dateutil.parser import parse

import logging
import re

# IP addres regex
# taken from this gist https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8
IPV4SEG  = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
IPV4ADDR = r'(?:(?:' + IPV4SEG + r'\.){3,3}' + IPV4SEG + r')'
IPV6SEG  = r'(?:(?:[0-9a-fA-F]){1,4})'
IPV6GROUPS = (
    r'(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,                  # 1:2:3:4:5:6:7:8
    r'(?:' + IPV6SEG + r':){1,7}:',                           # 1::                                 1:2:3:4:5:6:7::
    r'(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,                 # 1::8               1:2:3:4:5:6::8   1:2:3:4:5:6::8
    r'(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',  # 1::7:8             1:2:3:4:5::7:8   1:2:3:4:5::8
    r'(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',  # 1::6:7:8           1:2:3:4::6:7:8   1:2:3:4::8
    r'(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',  # 1::5:6:7:8         1:2:3::5:6:7:8   1:2:3::8
    r'(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',  # 1::4:5:6:7:8       1:2::4:5:6:7:8   1:2::8
    IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',             # 1::3:4:5:6:7:8     1::3:4:5:6:7:8   1::8
    r':(?:(?::' + IPV6SEG + r'){1,7}|:)',                     # ::2:3:4:5:6:7:8    ::2:3:4:5:6:7:8  ::8       ::
    r'fe80:(?::' + IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',       # fe80::7:8%eth0     fe80::7:8%1  (link-local IPv6 addresses with zone index)
    r'::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + IPV4ADDR,     # ::255.255.255.255  ::ffff:255.255.255.255  ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    r'(?:' + IPV6SEG + r':){1,4}:[^\s:]' + IPV4ADDR,          # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
)
IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])  # Reverse rows for greedy match

IP_RE = re.compile(r'.* (' + IPV4ADDR + '|' + IPV6ADDR + ')')


class NginxErrorLogFormatter (BaseFormatter):
    """
    Relies on the following parserts:
    <year/month/day hour:minute:sec> [<severity>] <cryptic_numbers> <error_description> client: <client>,
        server: <client>, request: <request>, host: <host>
    """
    levels = logging._levelNames
    activate_on_fname_suffix = ('error.log','error_log')

    def format_line (self, line, datadict, paramdict):
        tags = {
            "remote_ip": None,
            "hostname":  None,
            "referer":   None,
            "upstream":  None
        }
        try:
            dt = parse (line[:19])
        except ValueError:
            return datadict
        # Add date as a param and event date
        datadict['message'] = self.replace_param(line, datadict ['message'], '%s' % line[0:19], paramdict)
        datadict['date'] = dt

        # Add remote IP as a param
        client = re.findall(r'client: (' + IPV4ADDR + '|' + IPV6ADDR + ')\,', line)
        if client:
            datadict ['message'] = self.replace_param(line, datadict ['message'], client[0], paramdict)
            tags['remote_ip'] = client[0]

        # Add upstream to tags and params
        upstream = re.findall(r' upstream: "(.+?)"', line)
        if upstream:
            datadict ['message'] = self.replace_param(line, datadict ['message'], upstream[0], paramdict)
            _reg = re.compile('((.*?)//(.*?)\:\d+)/(.+)')
            tags['upstream'] = re.sub(_reg, '\g<1>', upstream[0])

        # Add server name
        server = re.findall(r'host: "(.+?)"', line)
        if server:
            datadict ['message'] = self.replace_param(line, datadict ['message'], server[0], paramdict)
            tags['hostname'] = server[0]

        severity = [p.strip().lstrip('[') for p in line[20:].split(']')][0]
        # Add loglevel
        loglvl = severity.upper()
        if not loglvl.isdigit() and loglvl in self.levels:
            datadict.setdefault('data',{})['level'] = self.levels[loglvl]

        # Add "cryptic numbers" as parameters for better grouping
        space_parts = line.split(' ')
        if space_parts[4].startswith('*'):
            cryptic_numbers = (' ').join(space_parts[3:5])
        else:
            cryptic_numbers = (' ').join(space_parts[3:4])
        if cryptic_numbers:
            datadict ['message'] = self.replace_param(line, datadict ['message'], cryptic_numbers, paramdict)

        # set the Referer field as the culprit
        ref = line.split('referrer: ')[-1]
        if ref != line:
            referer = ref.strip().strip('"')
            datadict['culprit'] = referer
            tags['referer'] = referer

        datadict.update({'tags': tags})

class ApacheErrorLogFormatter (BaseFormatter):
    """
    Relies on the following parts:
    [date] [severity] [client XXX] everything else
    """
    levels = logging._levelNames
    activate_on_fname_suffix = ('error.log','error_log')

    def format_line (self, line, datadict, paramdict):
        line_parts = [p.strip().lstrip('[') for p in line.split(']')]
        try:
            dt = parse (line_parts[0])
        except ValueError:
            return datadict
        # Add date as a param and event date
        datadict ['message'] = self.replace_param(line, datadict ['message'], '[%s]' % line_parts[0], paramdict)
        datadict ['date']= dt

        # Add remote IP as a param
        if len(line_parts)>3 and IP_RE.match (line_parts[2]):
            datadict ['message'] = self.replace_param(line, datadict ['message'], line_parts[2].split()[-1], paramdict)
        tags = {}

        # Tag virtualhost for MPM-ITK 503 error
        vhost = re.findall(r'MaxClientsVhost reached for (.+:\d{0,8}), refusing client', line)
        if vhost:
            tags.update({'host': re.sub(r':(\d+)?', '', vhost[0])})
        # Tag client IP
        client_ip = re.findall(IP_RE, line)
        if client_ip:
            tags.update({'client_ip': client_ip[0]})
        # Tag apache error code
        apache_error = re.findall(r'(AH0\d{3,4})', line)
        if apache_error:
            tags.update({'apache_code': apache_error[0]})

        if tags:
            datadict.update({'tags': tags})

        # Add loglevel
        try:
            loglvl = line_parts[1].upper()
            # Apache 2.4 log levels contains module name.
            if re.match(r'.+:.+', loglvl):
                loglvl = loglvl.split(':')[1]
        except IndexError:
            loglvl = 'NOTICE'
        if not loglvl.isdigit() and loglvl in self.levels:
            datadict.setdefault('data',{})['level'] = self.levels[loglvl]

        # set the Referer field as the culprit
        ref = line.split('referer: ')[-1]
        if ref!= line:
            datadict['culprit'] = ref.strip()


class FPMErrorLogFormatter (BaseFormatter):
    """
    Relies on the following parts:
    [DD-MON-YYY HH:MM:SS] severity: [pool name] error message
    """
    levels = logging._levelNames
    activate_on_fname_suffix = ('error.log','error_log')

    def format_line (self, line, datadict, paramdict):
        try:
            dt = parse(line[1:21])
        except ValueError:
            return datadict
        # Add date as a param and event date
        datadict['message'] = self.replace_param(line, datadict ['message'], '%s' % line[1:21], paramdict)
        datadict['date'] = dt

        # Add loglevel
        loglvl = re.findall(r'^(\w+):', line[23:])[0]
        if not loglvl.isdigit() and loglvl in self.levels:
            datadict.setdefault('data',{})['level'] = self.levels[loglvl]

        # Add pool name
        try:
            datadict['pool'] = re.findall(r'\[pool (\w+)\]', line)[0]
        except IndexError:
            pass