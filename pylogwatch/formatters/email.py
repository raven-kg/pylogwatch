# -*- coding: utf-8 -*-
from pylogwatch.formatters.base import BaseFormatter
from dateutil.parser import parse

import logging
import re


class EximPanicLogFormatter (BaseFormatter):
    activate_on_fname_suffix = ('panic.log','panic_log')
    def format_line(self, line, datadict, paramdict):
        try:
            dt = parse (line[:19])
        except ValueError:
            return datadict
        # Add date as a param and event date
        datadict['message'] = self.replace_param(line, datadict ['message'], '%s' % line[0:19], paramdict)
        datadict['date'] = dt

        msg_id = re.findall(r'[\w]{6}-[\w]{6}-[\w]{1,2}', line)
        if msg_id:
            datadict ['message'] = self.replace_param(line, datadict ['message'], msg_id[0], paramdict)

