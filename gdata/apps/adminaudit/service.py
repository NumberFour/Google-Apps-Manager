#!/usr/bin/python2.4
#
# Copyright 2010 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""AdminAuditService simplifies Admin Audit API calls.

AdminAuditService extends gdata.apps.service.PropertyService to ease interaction with
the Google Apps Admin Audit API.
"""

__author__ = 'Jay Lee <jay0lee@gmail.com>'

import gdata.apps
import gdata.apps.service
import gdata.service
import json


class AdminAuditService(gdata.apps.service.PropertyService):
  """Service extension for the Google Admin Audit API service."""

  def __init__(self, email=None, password=None, domain=None, source=None,
               server='www.googleapis.com', additional_headers=None,
               **kwargs):
    """Creates a client for the Admin Audit service.

    Args:
      email: string (optional) The user's email address, used for
          authentication.
      password: string (optional) The user's password.
      domain: string (optional) The Google Apps domain name.
      source: string (optional) The name of the user's application.
      server: string (optional) The name of the server to which a connection
          will be opened. Default value: 'apps-apis.google.com'.
      **kwargs: The other parameters to pass to gdata.service.GDataService
          constructor.
    """
    gdata.service.GDataService.__init__(
        self, email=email, password=password, service='apps', source=source,
        server=server, additional_headers=additional_headers, **kwargs)
    self.ssl = True
    self.port = 443
    self.domain = domain

  def retrieve_audit(self, customer_id, admin=None, event=None, start_date=None, end_date=None):
    """Retrieves an audit

    """
    uri = '/apps/reporting/audit/v1/%s/207535951991' % customer_id
    amp = False
    if admin != None:
      uri += '?actorEmail=%s' % admin
      amp = True
    if event != None:
      if not amp:
        uri += '&eventName=%s' % event
        amp = True
      else:
        uri += '?eventName=%s' % event
    if start_date != None:
      if not amp:
        uri += '&startTime=%s' % start_date
        amp = True
      else:
        uri += '?startTime=%s' % start_date
    if end_date != None:
      if not amp:
        uri += '&endTime=%s' % end_date
      else:
        uri += '?endTime=%s' % end_date
        
    json_data = self.Get(uri, converter=str)
    #return json.loads(json_data)
    return json_data

  RetrieveAudit = retrieve_audit