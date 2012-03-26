#!/usr/bin/env python
#
# Google Apps Manager
#
# Copyright 2012 Dito, LLC All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Google Apps Manager (GAM) is a command line tool which allows Administrators to control their Google Apps domain and accounts.

With GAM you can programatically create users, turn on/off services for users like POP and Forwarding and much more.
For more information, see http://code.google.com/p/google-apps-manager

"""

__author__ = 'jay@ditoweb.com (Jay Lee)'
__version__ = '2.3'
__license__ = 'Apache License 2.0 (http://www.apache.org/licenses/LICENSE-2.0)'

import sys, os, time, datetime, random, cgi, socket, urllib, csv, getpass, platform, re, webbrowser, pickle
import xml.dom.minidom
from sys import exit
import gdata.apps.service
import gdata.apps.emailsettings.service
import gdata.apps.adminsettings.service
import gdata.apps.groups.service
import gdata.apps.audit.service
try:
  import gdata.apps.adminaudit.service
except ImportError:
  pass
import gdata.apps.multidomain.service
import gdata.apps.orgs.service
import gdata.apps.res_cal.service
import gdata.calendar
import gdata.calendar.service
import gdata.apps.groupsettings.service
import gdata.apps.reporting.service

import gdata.auth
import atom
import gdata.contacts
import gdata.contacts.service
from hashlib import sha1


def showUsage():
  doGAMVersion()
  print '''
Usage: gam [OPTIONS]...

Google Apps Manager. Retrieve or set Google Apps domain,
user, group and alias settings. Exhaustive list of commands
can be found at: http://code.google.com/p/google-apps-manager/wiki

Examples:
gam info domain
gam create user jsmith firstname John lastname Smith password secretpass
gam update user jsmith suspended on
gam.exe update group announcements add member jsmith
...

'''
def getGamPath():
  if os.name == 'windows':
    divider = '\\'
  else:
    divider = '/'
  return os.path.dirname(os.path.realpath(sys.argv[0]))+divider

def doGAMVersion():
  print 'Google Apps Manager %s\r\n%s\r\nPython %s.%s.%s %s\r\n%s %s' % (__version__, __author__,
                   sys.version_info[0], sys.version_info[1], sys.version_info[2],
                   sys.version_info[3], platform.platform(), platform.machine())

def commonAppsObjInit(appsObj):
  #Identify GAM to Google's Servers
  appsObj.source = 'Google Apps Manager %s / %s / Python %s.%s.%s %s / %s %s /' % (__version__, __author__,
                   sys.version_info[0], sys.version_info[1], sys.version_info[2],
                   sys.version_info[3], platform.platform(), platform.machine())
  #Show debugging output if debug.gam exists
  if os.path.isfile(getGamPath()+'debug.gam'):
    appsObj.debug = True
  return appsObj

def tryOAuth(gdataObject):
  global domain
  oauth_filename = 'oauth.txt'
  try:
    oauth_filename = os.environ['OAUTHFILE']
  except KeyError:
    pass
  if os.path.isfile(getGamPath()+oauth_filename):
    oauthfile = open(getGamPath()+oauth_filename, 'rb')
    domain = oauthfile.readline()[0:-1]
    try:
      token = pickle.load(oauthfile)
      oauthfile.close()
    except ImportError: # Deals with tokens created by windows on old GAM versions. Rewrites them with binary mode set
      oauthfile = open(getGamPath()+oauth_filename, 'r')
      domain = oauthfile.readline()[0:-1]
      token = pickle.load(oauthfile)
      oauthfile.close()
      f = open(getGamPath()+oauth_filename, 'wb')
      f.write('%s\n' % (domain,))
      pickle.dump(token, f)
      f.close()
    gdataObject.domain = domain
    gdataObject.SetOAuthInputParameters(gdata.auth.OAuthSignatureMethod.HMAC_SHA1, consumer_key=token.oauth_input_params._consumer.key, consumer_secret=token.oauth_input_params._consumer.secret)
    token.oauth_input_params = gdataObject._oauth_input_params
    gdataObject.SetOAuthToken(token)
    return True
  else:
    return False

def getAppsObject():
  apps = gdata.apps.service.AppsService()
  if not tryOAuth(apps):
    doRequestOAuth()
    tryOAuth(apps)
  apps = commonAppsObjInit(apps)
  return apps

def getProfilesObject():
  profiles = gdata.contacts.service.ContactsService(contact_list='domain')
  profiles.ssl = True
  if not tryOAuth(profiles):
    doRequestOAuth()
    tryOAuth(profiles)
  profiles = commonAppsObjInit(profiles)
  return profiles

def getCalendarObject():
  calendars = gdata.calendar.service.CalendarService()
  calendars.ssl = True
  if not tryOAuth(calendars):
    doRequestOAuth()
    tryOAuth(calendars)
  calendars = commonAppsObjInit(calendars)
  return calendars

def getGroupSettingsObject():
  groupsettings = gdata.apps.groupsettings.service.GroupSettingsService()
  if not tryOAuth(groupsettings):
    doRequestOAuth()
    tryOAuth(groupsettings)
  groupsettings = commonAppsObjInit(groupsettings)
  return groupsettings

def getEmailSettingsObject():
  emailsettings = gdata.apps.emailsettings.service.EmailSettingsService()
  if not tryOAuth(emailsettings):
    doRequestOAuth()
    tryOAuth(emailsettings)
  emailsettings = emailsettings = commonAppsObjInit(emailsettings)
  return emailsettings

def getAdminSettingsObject():
  global domain
  adminsettings = gdata.apps.adminsettings.service.AdminSettingsService()
  if not tryOAuth(adminsettings):
    doRequestOAuth()
    tryOAuth(adminsettings)
  adminsettings = commonAppsObjInit(adminsettings)
  return adminsettings
  
def getGroupsObject():
  global domain
  groupsObj = gdata.apps.groups.service.GroupsService()
  if not tryOAuth(groupsObj):
    doRequestOAuth()
    tryOAuth(groupsObj)
  groupsObj = commonAppsObjInit(groupsObj)
  return groupsObj

def getAuditObject():
  auditObj = gdata.apps.audit.service.AuditService()
  if not tryOAuth(auditObj):
    doRequestOAuth()
    tryOAuth(auditObj)
  auditObj = commonAppsObjInit(auditObj)
  return auditObj

def getAdminAuditObject():
  try:
    adminAuditObj = gdata.apps.adminaudit.service.AdminAuditService()
  except AttributeError:
    print "gam audit admin commands require Python 2.6 or 2.7"
    sys.exit(3)
  if not tryOAuth(adminAuditObj):
    doRequestOAuth()
    tryOAuth(adminAuditObj)
  adminAuditObj = commonAppsObjInit(adminAuditObj)
  return adminAuditObj

def getMultiDomainObject():
  multidomainObj = gdata.apps.multidomain.service.MultiDomainService()
  if not tryOAuth(multidomainObj):
    doRequestOAuth()
    tryOAuth(multidomainObj)
  multidomainObj = commonAppsObjInit(multidomainObj)
  return multidomainObj

def getOrgObject():
  orgObj = gdata.apps.orgs.service.OrganizationService()
  if not tryOAuth(orgObj):
    doRequestOAuth()
    tryOAuth(orgObj)
  orgObj = commonAppsObjInit(orgObj)
  return orgObj

def getResCalObject():
  resCalObj = gdata.apps.res_cal.service.ResCalService()
  if not tryOAuth(resCalObj):
    doRequestOAuth()
    tryOAuth(resCalObj)
  resCalObj = commonAppsObjInit(resCalObj)
  return resCalObj

def getRepObject():
  repObj = gdata.apps.reporting.service.ReportService()
  if not tryOAuth(repObj):
    doRequestOAuth()
    tryOAuth(repObj)
  repObj = commonAppsObjInit(repObj)
  return repObj

def _reporthook(numblocks, blocksize, filesize, url=None):
    #print "reporthook(%s, %s, %s)" % (numblocks, blocksize, filesize)
    base = os.path.basename(url)
    #XXX Should handle possible filesize=-1.
    try:
        percent = min((numblocks*blocksize*100)/filesize, 100)
    except:
        percent = 100
    if numblocks != 0:
        sys.stdout.write("\b"*70)
    sys.stdout.write(str(percent)+'% ')
    #print str(percent)+"%\b\b"

def geturl(url, dst):
    if sys.stdout.isatty():
        urllib.urlretrieve(url, dst,
                           lambda nb, bs, fs, url=url: _reporthook(nb,bs,fs,url))
        sys.stdout.write('\n')
    else:
        urllib.urlretrieve(url, dst)

def showReport():
  report = sys.argv[2].lower()
  date = page = None
  if len(sys.argv) > 3:
    date = sys.argv[3]
  rep = getRepObject()
  report_data = rep.retrieve_report(report=report, date=date)
  sys.stdout.write(report_data)

def doDelegates(users):
  emailsettings = getEmailSettingsObject()
  if sys.argv[4].lower() == 'to':
    delegate = sys.argv[5].lower()
    #delegate needs to be a full email address, tack
    #on domain of 1st user if there isn't one
    if not delegate.find('@') > 0:
      delegate_domain = domain.lower()
      delegate_email = '%s@%s' % (delegate, delegate_domain)
    else:
      delegate_domain = delegate[delegate.find('@')+1:].lower()
      delegate_email = delegate
  else:
    showUsage()
    exit(6)
  count = len(users)
  i = 1
  for delegator in users:
    if delegator.find('@') > 0:
      delegator_domain = delegator[delegator.find('@')+1:].lower()
      delegator_email = delegator
      delegator = delegator[:delegator.find('@')]
    else:
      delegator_domain = domain.lower()
      delegator_email = '%s@%s' % (delegator, delegator_domain)
    emailsettings.domain = delegator_domain
    print "Giving %s delegate access to %s (%s of %s)" % (delegate_email, delegator_email, i, count)
    delete_alias = False
    if delegate_domain == delegator_domain:
      use_delegate_address = delegate_email
    else:
      # Need to use an alias in delegator domain, first check to see if delegate already has one...
      multi = getMultiDomainObject()
      aliases = multi.GetUserAliases(delegate_email)
      found_alias_in_delegator_domain = False
      for alias in aliases:
        alias_domain = alias['aliasEmail'][alias['aliasEmail'].find('@')+1:].lower()
        if alias_domain == delegator_domain:
          use_delegate_address = alias['aliasEmail']
          print '  Using existing alias %s for delegation' % use_delegate_address
          found_alias_in_delegator_domain = True
          break
      if not found_alias_in_delegator_domain:
        delete_alias = True
        use_delegate_address = '%s@%s' % (''.join(random.sample('abcdefghijklmnopqrstuvwxyz0123456789', 10)), delegator_domain)
        print '  Giving %s temporary alias %s for delegation' % (delegate_email, use_delegate_address)
        multi.CreateAlias(user_email=delegate_email, alias_email=use_delegate_address)
        time.sleep(5)
    try:
      emailsettings.CreateDelegate(delegate=use_delegate_address, delegator=delegator)
    except gdata.apps.service.AppsForYourDomainException, e:
      print e
      time.sleep(10)
      sys.exit(5)
    time.sleep(10)
    if delete_alias:
      print '  Deleting temporary alias...'
      multi.DeleteAlias(use_delegate_address)
    i = i + 1

def getDelegates(users):
  emailsettings = getEmailSettingsObject()
  csv_format = False
  try:
    if sys.argv[5].lower() == 'csv':
      csv_format = True
  except IndexError:
    pass
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    sys.stderr.write("Getting delegates for %s...\n" % (user + '@' + emailsettings.domain))
    try:
      delegates = emailsettings.GetDelegates(delegator=user)
    except gdata.apps.service.AppsForYourDomainException, e:
      sys.stderr.write(e)
    for delegate in delegates:
      if csv_format:
        print '%s,%s,%s' % (user + '@' + emailsettings.domain, delegate['address'], delegate['status'])
      else:
        print "Delegator: %s\n Delegate: %s\n Status: %s\n Delegate Email: %s\n Delegate ID: %s\n" % (user, delegate['delegate'], delegate['status'], delegate['address'], delegate['delegationId'])

def deleteDelegate(users):
  emailsettings = getEmailSettingsObject()
  delegate = sys.argv[5]
  if not delegate.find('@') > 0:
    if users[0].find('@') > 0:
      delegatedomain = users[0][users[0].find('@')+1:]
    else:
      delegatedomain = domain
    delegate = delegate+'@'+delegatedomain
  count = len(users)
  i = 1
  for user in users:
    print "Deleting %s delegate access to %s (%s of %s)" % (delegate, user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.DeleteDelegate(delegate=delegate, delegator=user)
    i = i + 1

def deleteCalendar(users):
  del_cal = sys.argv[5]
  cal = getCalendarObject()
  for user in users:
    if user.find('@') > 0:
      user_domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      user_domain = domain
    uri = 'https://www.google.com/calendar/feeds/%s/allcalendars/full/%s' % (user+'@'+user_domain, del_cal)
    try:
      calendar_entry = cal.GetCalendarListEntry(uri)
    except gdata.service.RequestError, e:
      print 'Error: %s - %s' % (e[0]['reason'], e[0]['body'])
      continue
    try:
      edit_uri = calendar_entry.GetEditLink().href
      cal.DeleteCalendarEntry(edit_uri)
    except gdata.service.RequestError, e:
      print 'Error: %s - %s' % (e[0]['reason'], e[0]['body'])

def addCalendar(users):
  add_cal = sys.argv[5]
  cal = getCalendarObject()
  selected = hidden = color = None
  i = 6
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'selected':
      if sys.argv[i+1].lower() == 'true':
		selected = 'true'
      elif sys.argv[i+1].lower() == 'false':
		selected = 'false'
      else:
        showUsage()
        print 'Value for selected must be true or false, not %s' % sys.argv[i+1]
        exit(4)
      i = i + 2
    elif sys.argv[i].lower() == 'hidden':
      if sys.argv[i+1].lower() == 'true':
		hidden = 'true'
      elif sys.argv[i+1].lower() == 'false':
        calendar_entry.hidden =  gdata.calendar.Hidden(value='false')
        hidden = 'false'
      else:
        showUsage()
        print 'Value for hidden must be true or false, not %s' % sys.argv[i+1]
        exit(4)
      i = i + 2
    elif sys.argv[i].lower() == 'color':
      color = sys.argv[i+1]
      i = i + 2
    else:
      showUsage()
      print '%s is not a valid argument for "gam add calendar"' % sys.argv[i]
  for user in users:
    if user.find('@') > 0:
      user_domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
	    user_domain = domain
    calendar_entry = gdata.calendar.CalendarListEntry()
    try:
      insert_uri = 'https://www.google.com/calendar/feeds/%s/allcalendars/full' % (user+'@'+user_domain)
      calendar_entry.id = atom.Id(text=add_cal)
      calendar_entry.hidden = gdata.calendar.Hidden(value=hidden)
      calendar_entry.selected =  gdata.calendar.Selected(value=selected)
      if color != None:
        calendar_entry.color = gdata.calendar.Color(value=color)
      cal.InsertCalendarSubscription(insert_uri=insert_uri, calendar=calendar_entry)
    except gdata.service.RequestError, e:
      print 'Error: %s - %s' % (e[0]['reason'], e[0]['body'])
      continue

def updateCalendar(users):
  update_cal = sys.argv[5]
  cal = getCalendarObject()
  selected = hidden = color = None
  i = 6
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'selected':
      if sys.argv[i+1].lower() == 'true':
		selected = 'true'
      elif sys.argv[i+1].lower() == 'false':
		selected = 'false'
      else:
        showUsage()
        print 'Value for selected must be true or false, not %s' % sys.argv[i+1]
        exit(4)
      i = i + 2
    elif sys.argv[i].lower() == 'hidden':
      if sys.argv[i+1].lower() == 'true':
		hidden = 'true'
      elif sys.argv[i+1].lower() == 'false':
        calendar_entry.hidden =  gdata.calendar.Hidden(value='false')
        hidden = 'false'
      else:
        showUsage()
        print 'Value for hidden must be true or false, not %s' % sys.argv[i+1]
        exit(4)
      i = i + 2
    elif sys.argv[i].lower() == 'color':
      color = sys.argv[i+1]
      i = i + 2
    else:
      showUsage()
      print '%s is not a valid argument for "gam add calendar"' % sys.argv[i]
  for user in users:
    if user.find('@') > 0:
      user_domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      user_domain = domain
    uri = 'https://www.google.com/calendar/feeds/%s/allcalendars/full/%s' % (user+'@'+user_domain, update_cal)
    try:
      calendar_entry = cal.GetCalendarListEntry(uri)
    except gdata.service.RequestError, e:
      print 'Error: %s - %s' % (e[0]['reason'], e[0]['body'])
      continue
    if selected != None:
	  calendar_entry.selected =  gdata.calendar.Selected(value=selected)
    if hidden != None:
	  calendar_entry.hidden =  gdata.calendar.Hidden(value=hidden)
    if color != None:
	  calendar_entry.color = gdata.calendar.Color(value=color)
    try:
      edit_uri = calendar_entry.GetEditLink().href
      cal.UpdateCalendar(calendar_entry)
    except gdata.service.RequestError, e:
      print 'Error: %s - %s' % (e[0]['reason'], e[0]['body'])
      continue

def doCalendarShowACL():
  show_cal = sys.argv[2]
  cal = getCalendarObject()
  uri = 'https://www.google.com/calendar/feeds/%s/acl/full' % (show_cal)
  feed = cal.GetCalendarAclFeed(uri=uri)
  print feed.title.text
  for i, a_rule in enumerate(feed.entry):
    print '  Scope %s - %s' % (a_rule.scope.type, a_rule.scope.value)
    print '  Role: %s' % (a_rule.title.text)
    print ''

def doCalendarAddACL():
  use_cal = sys.argv[2]
  role = sys.argv[4].lower()
  if role != 'freebusy' and role != 'read' and role != 'editor' and role != 'owner':
    print 'Error: Role must be freebusy, read, editor or owner. Not %s' % role
    exit (33)
  user_to_add = sys.argv[5]
  cal = getCalendarObject()
  rule = gdata.calendar.CalendarAclEntry()
  rule.scope = gdata.calendar.Scope(value=user_to_add)
  rule.scope.type = 'user'
  roleValue = 'http://schemas.google.com/gCal/2005#%s' % (role)
  rule.role = gdata.calendar.Role(value=roleValue)
  aclUrl = '/calendar/feeds/%s/acl/full' % use_cal
  try:
    returned_rule = cal.InsertAclEntry(rule, aclUrl)
  except gdata.service.RequestError, e:
      print 'Error: %s - %s' % (e[0]['reason'], e[0]['body'])

def doCalendarUpdateACL():
  use_cal = sys.argv[2]
  role = sys.argv[4].lower()
  if role != 'freebusy' and role != 'read' and role != 'editor' and role != 'owner':
    print 'Error: Role must be freebusy, read, editor or owner. Not %s' % role
    exit (33)
  user_to_add = sys.argv[5]
  cal = getCalendarObject()
  rule = gdata.calendar.CalendarAclEntry()
  if user_to_add.lower() == 'domain':
    rule_value = cal.domain
    rule_type = 'domain'
  elif user_to_add.lower() == 'default':
    rule_value = None
    rule_type = 'default'
  else:
    rule_value = user_to_add
    rule_type = 'user'
  rule.scope = gdata.calendar.Scope(value=rule_value)
  rule.scope.type = rule_type
  roleValue = 'http://schemas.google.com/gCal/2005#%s' % (role)
  rule.role = gdata.calendar.Role(value=roleValue)
  if rule_type != 'default':
    aclUrl = '/calendar/feeds/%s/acl/full/%s%%3A%s' % (use_cal, rule_type, rule_value)
  else:
    aclUrl = '/calendar/feeds/%s/acl/full/default' % (use_cal)
  try:
    returned_rule = cal.UpdateAclEntry(edit_uri=aclUrl, updated_rule=rule)
  except gdata.service.RequestError, e:
      print 'Error: %s - %s' % (e[0]['reason'], e[0]['body'])

def doCalendarDelACL():
  use_cal = sys.argv[2]
  if sys.argv[4].lower() != 'user':
    print 'invalid syntax'
    exit(9)
  user_to_del = sys.argv[5].lower()
  cal = getCalendarObject()
  uri = 'https://www.google.com/calendar/feeds/%s/acl/full' % (use_cal)
  feed = cal.GetCalendarAclFeed(uri=uri)
  found_rule = False
  for i, a_rule in enumerate(feed.entry):
    if a_rule.scope.value.lower() == user_to_del:
      found_rule = True
      result = cal.DeleteAclEntry(a_rule.GetEditLink().href)
  if not found_rule:
    print 'Error: that object does not seem to have access to that calendar'
    exit(34)

def doProfile(users):
  if sys.argv[4].lower() == 'share' or sys.argv[4].lower() == 'shared':
    indexed = 'true'
  elif sys.argv[4].lower() == 'unshare' or sys.argv[4].lower() == 'unshared':
    indexed = 'false'
  profiles = getProfilesObject()
  count = len(users)
  i = 1
  for user in users:
    if user.find('@') > 0:
      user_domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      user_domain = domain
    print 'Setting Profile Sharing to %s for %s@%s (%s of %s)' % (indexed, user, user_domain, i, count)
    uri = '/m8/feeds/profiles/domain/%s/full/%s?v=3.0' % (user_domain, user)
    try:
      user_profile = profiles.GetProfile(uri)
      user_profile.extension_elements[2].attributes['indexed'] = indexed
      profiles.UpdateProfile(user_profile.GetEditLink().href, user_profile)
    except gdata.service.RequestError, e:
      print 'Error for %s@%s: %s - %s' % (user, user_domain, e[0]['body'], e[0]['reason'])
    i += 1

def showProfile(users):
  profiles = getProfilesObject()
  for user in users:
    if user.find('@') > 0:
      user_domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      user_domain = domain
    uri = '/m8/feeds/profiles/domain/%s/full/%s?v=3.0' % (user_domain, user)
    try:
      user_profile = profiles.GetProfile(uri)
    except gdata.service.RequestError, e:
      print 'Error for %s@%s: %s - %s' % (user, user_domain, e[0]['body'], e[0]['reason'])
      continue
    indexed = user_profile.extension_elements[2].attributes['indexed']
    print '''User: %s@%s
 Profile Shared: %s''' % (user, user_domain, indexed)

def doPhoto(users):
  filename = sys.argv[5]
  profiles = getProfilesObject()
  i = 1
  count = len(users)
  for user in users:
    if user.find('@') > 0:
      user_domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      user_domain = domain
    uri = '/m8/feeds/profiles/domain/%s/full/%s?v=3' % (user_domain, user)
    try:
      user_profile = profiles.GetProfile(uri)
      photo_uri = user_profile.link[0].href
      try:
        if sys.argv[6].lower() == 'nooverwrite':
          etag = user_profile.link[0].extension_attributes['{http://schemas.google.com/g/2005}etag']
          print 'Not overwriting existing photo for %s@%s' % (user, user_domain)
          continue
      except IndexError:
        pass
      except KeyError:
        pass
      print "Updating photo for %s (%s of %s)" % (user+'@'+user_domain, i, count)
      results = profiles.ChangePhoto(media=filename, content_type='image/jpeg', contact_entry_or_url=photo_uri)
    except gdata.service.RequestError, e:
      print 'Error for %s@%s: %s - %s' % (user, user_domain, e[0]['body'], e[0]['reason'])
    i = i + 1

def getPhoto(users):
  profiles = getProfilesObject()
  i = 1
  count = len(users)
  for user in users:
    if user.find('@') > 0:
      user_domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      user_domain = domain
    uri = '/m8/feeds/profiles/domain/%s/full/%s?v=3' % (user_domain, user)
    try:
      user_profile = profiles.GetProfile(uri)
      try:
        etag = user_profile.link[0].extension_attributes['{http://schemas.google.com/g/2005}etag']
      except KeyError:
        print '  No photo for %s@%s' % (user, user_domain)
        i = i + 1
        continue
      photo_uri = user_profile.link[0].href
      filename = '%s-%s.jpg' % (user, user_domain)
      print "Saving photo for %s to %s (%s of %s)" % (user+'@'+user_domain, filename, i, count)
      photo = profiles.GetPhoto(contact_entry_or_url=photo_uri)
    except gdata.service.RequestError, e:
      print '  Error for %s@%s: %s - %s' % (user, user_domain, e[0]['body'], e[0]['reason'])
      i = i + 1  
      continue
    photo_file = open(filename, 'wb')
    photo_file.write(photo)
    photo_file.close()
    i = i + 1

def deletePhoto(users):
  profiles = getProfilesObject()
  i = 1
  count = len(users)
  for user in users:
    if user.find('@') > 0:
      user_domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      user_domain = domain
    uri = '/m8/feeds/profiles/domain/%s/full/%s?v=3' % (user_domain, user)
    try:
      user_profile = profiles.GetProfile(uri)
      photo_uri = user_profile.link[0].href
      print "Deleting photo for %s (%s of %s)" % (user+'@'+user_domain, i, count)
      results = profiles.DeletePhoto(photo_uri)
    except gdata.service.RequestError, e:
      print 'Error for %s@%s: %s - %s' % (user, user_domain, e[0]['body'], e[0]['reason'])
    i = i + 1

def showCalendars(users):
  cal = getCalendarObject()
  for user in users:
    if user.find('@') > 0:
      user_domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      user_domain = domain
    uri = '/calendar/feeds/%s/allcalendars/full' % (user+'@'+user_domain,)
    feed = cal.GetAllCalendarsFeed(uri)
    print '%s' % feed.title.text
    for i, a_calendar in enumerate(feed.entry):
      print '  Name: %s' % str(a_calendar.title.text)
      print '    ID: %s' % urllib.unquote(str(a_calendar.id.text).rpartition('/')[2])
      print '    Access Level: %s' % str(a_calendar.access_level.value)
      print '    Timezone: %s' % str(a_calendar.timezone.value)
      print '    Hidden: %s' % str(a_calendar.hidden.value)
      print '    Selected: %s' % str(a_calendar.selected.value)
      print '    Color: %s' % str(a_calendar.color.value)
      print ''

def showCalSettings(users):
  cal = getCalendarObject()
  for user in users:
    if user.find('@') > 0:
      user_domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      user_domain = domain
    uri = '/calendar/feeds/%s/settings' % (user+'@'+user_domain)
    #uri = '/calendar/feeds/default/settings'
    try:
      feed = cal.GetCalendarSettingsFeed(uri)
    except gdata.service.RequestError, e:
      print 'Error: %s - %s' % (e[0]['reason'], e[0]['body'])
      sys.exit(59)
    print feed.title.text
    for i, a_setting in enumerate(feed.entry):
      print ' %s: %s' % (a_setting.extension_elements[0].attributes['name'], a_setting.extension_elements[0].attributes['value'])

def doImap(users):
  checkTOS = True
  if sys.argv[4].lower() == 'on':
    enable = True
  elif sys.argv[4].lower() == 'off':
    enable = False
  if len(sys.argv) > 5 and sys.argv[5] == 'noconfirm':
    checkTOS = False
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Setting IMAP Access to %s for %s (%s of %s)" % (str(enable), user, i, count)
    if checkTOS:
      if not hasAgreed2TOS(user):
        print ' Warning: IMAP has been enabled but '+user+' has not logged into GMail to agree to the terms of service (captcha).  IMAP will not work until they do.'
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.UpdateImap(username=user, enable=enable)
    i = i + 1

def getImap(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    imapsettings = emailsettings.GetImap(username=user)
    print 'User %s  IMAP Enabled:%s' % (user, imapsettings['enable'])

def doPop(users):
  checkTOS = True
  if sys.argv[4].lower() == 'on':
    enable = True
  elif sys.argv[4].lower() == 'off':
    enable = False
  i = 5
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'for':
      if sys.argv[i+1].lower() == 'allmail':
        enable_for = 'ALL_MAIL'
        i = i + 2
      elif sys.argv[i+1].lower() == 'newmail':
        enable_for = 'MAIL_FROM_NOW_ON'
        i = i + 2
    elif sys.argv[i].lower() == 'action':
      if sys.argv[i+1].lower() == 'keep':
        action = 'KEEP'
        i = i + 2
      elif sys.argv[i+1].lower() == 'archive':
        action = 'ARCHIVE'
        i = i + 2
      elif sys.argv[i+1].lower() == 'delete':
        action = 'DELETE'
        i = i + 2
    elif sys.argv[i].lower() == 'noconfirm':
      checkTOS = False
      i = i + 1
    else:
      showUsage()
      sys.exit(2)
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Setting POP Access to %s for %s (%s of %s)" % (str(enable), user, i, count)
    if checkTOS:
      if not hasAgreed2TOS(user):
        print ' Warning: POP has been enabled but '+user+' has not logged into GMail to agree to the terms of service (captcha).  POP will not work until they do.'
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.UpdatePop(username=user, enable=enable, enable_for=enable_for, action=action)
    i = i + 1

def getPop(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    popsettings = emailsettings.GetPop(username=user)
    print 'User %s  POP Enabled:%s  Action:%s' % (user, popsettings['enable'], popsettings['action'])

def doSendAs(users):
  sendas = sys.argv[4]
  sendasName = sys.argv[5]
  make_default = reply_to = None
  i = 6
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'default':
      make_default = True
      i = i + 1
    elif sys.argv[i].lower() == 'replyto':
      reply_to = sys.argv[i+1]
      i = i + 2
    else:
      showUsage()
      sys.exit(2)
  emailsettings = getEmailSettingsObject()
  if sendas.find('@') < 0:
    sendas = sendas+'@'+domain
  count = len(users)
  i = 1
  for user in users:
    print "Allowing %s to send as %s (%s of %s)" % (user, sendas, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.CreateSendAsAlias(username=user, name=sendasName, address=sendas, make_default=make_default, reply_to=reply_to)
    i = i + 1

def showSendAs(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    print '%s has the following send as aliases:' %  user
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    sendases = emailsettings.GetSendAsAlias(username=user) 
    for sendas in sendases:
      if sendas['isDefault'] == 'true':
        default = 'yes'
      else:
        default = 'no'
      if sendas['replyTo']:
        replyto = ' Reply To:<'+sendas['replyTo']+'>'
      else:
        replyto = ''
      if sendas['verified'] == 'true':
        verified = 'yes'
      else:
        verified = 'no'
      print ' "%s" <%s>%s Default:%s Verified:%s' % (sendas['name'], sendas['address'], replyto, default, verified)
    print ''

def doLanguage(users):
  language = sys.argv[4].lower()
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Setting the language for %s to %s (%s of %s)" % (user, language, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.UpdateLanguage(username=user, language=language)
    i = i + 1

def doUTF(users):
  if sys.argv[4].lower() == 'on':
    SetUTF = True
  elif sys.argv[4].lower() == 'off':
    SetUTF = False
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Setting UTF-8 to %s for %s (%s of %s)" % (str(SetUTF), user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.UpdateGeneral(username=user, unicode=SetUTF)
    i = i + 1

def doPageSize(users):
  if sys.argv[4] == '25':
    PageSize = '25'
  elif sys.argv[4] == '50':
    PageSize = '50'
  elif sys.argv[4] == '100':
    PageSize = '100'
  else:
    showUsage()
    sys.exit(2)
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Setting Page Size to %s for %s (%s of %s)" % (PageSize, user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.UpdateGeneral(username=user, page_size=PageSize)
    i = i + 1

def doShortCuts(users):
  if sys.argv[4].lower() == 'on':
    SetShortCuts = True
  elif sys.argv[4].lower() == 'off':
    SetShortCuts = False
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Setting Keyboard Short Cuts to %s for %s (%s of %s)" % (str(SetShortCuts), user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.UpdateGeneral(username=user, shortcuts=SetShortCuts)
    i = i + 1

def doAdminAudit():
  i = 3
  admin = event = start_date = end_date = None
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'admin':
      admin = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'event':
      event = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'start_date':
      start_date = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'end_date':
      end_date = sys.argv[i+1]
      i = i + 2
    else:
      showUsage()
      sys.exit(2)
  orgs = getOrgObject()
  customer_id = orgs.RetrieveCustomerId()['customerId']
  aa = getAdminAuditObject()
  results = aa.retrieve_audit(customer_id=customer_id, admin=admin, event=event, start_date=start_date, end_date=end_date)
  #for result in results['items']:
  #  pp.pprint(result)
  #  print ''
  print results
  sys.exit(0)
  for result in results['items']:
    #print result['events'][0]['name']
    #print result['actor']['email']
    event_name = result['events'][0]['name']
    description = ''
    if event_name == 'RENAME_USER':
      description = '%s has been renamed to %s' % (result['events'][0]['parameters'][0]['value'], result['events'][0]['parameters'][1]['value'])
    elif event_name == 'CHANGE_PASSWORD':
      description = 'Password has been changed for %s' % result['events'][0]['parameters'][0]['value']
    elif event_name == 'REMOVE_NICKNAME':
      description = '%s is removed as a nickname of %s' % (result['events'][0]['parameters'][0]['value'], result['events'][0]['parameters'][1]['value'])
    elif event_name == 'CHANGE_CALENDAR_SETTING':
      #print result['events'][0]['parameters']
      print result
      description = '%s for calendar service on %s has been changed from %s to %s' % (result['events'][0]['parameters'][0]['value'], result['events']['DOMAIN_NAME'], result['events'][0]['parameters'][0]['OLD_VALUE'], result['events'][0]['parameters'][0]['NEW_VALUE'])
    print '%s,%s,%s,%s,%s' % (event_name, description, result['actor']['email'], result['ipAddress'], result['id']['time'])
    #exit(0)
  
def doArrows(users):
  if sys.argv[4].lower() == 'on':
    SetArrows = True
  elif sys.argv[4].lower() == 'off':
    SetArrows = False
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Setting Personal Indicator Arrows to %s for %s (%s of %s)" % (str(SetArrows), user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.UpdateGeneral(username=user, arrows=SetArrows)
    i = i + 1

def doSnippets(users):
  if sys.argv[4].lower() == 'on':
    SetSnippets = True
  elif sys.argv[4].lower() == 'off':
    SetSnippets = False
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Setting Preview Snippets to %s for %s (%s of %s)" % (str(SetSnippets), user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.UpdateGeneral(username=user, snippets=SetSnippets)
    i = i + 1

def doLabel(users):
  label = sys.argv[4]
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Creating label %s for %s (%s of %s)" % (label, user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.CreateLabel(username=user, label=label)
    i = i + 1

def doDeleteLabel(users):
  label = sys.argv[5]
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Deleting label %s for %s (%s of %s)" % (label, user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    try:
      results = emailsettings.DeleteLabel(username=user, label=label)
    except gdata.service.RequestError, e:
      print e
    i = i + 1

def showLabels(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    print '%s has the following labels:' %  user
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    labels = emailsettings.GetLabels(username=user)
    for label in labels:
      print ' %s  Unread:%s  Visibility:%s' % (label['label'], label['unreadCount'], label['visibility'])
    print ''

def doFilter(users):
  i = 4 # filter arguments start here
  from_ = to = subject = has_the_word = does_not_have_the_word = has_attachment = label = should_mark_as_read = should_archive = should_star = forward_to = should_trash = should_not_spam = None
  haveCondition = False
  while sys.argv[i].lower() == 'from' or sys.argv[i].lower() == 'to' or sys.argv[i].lower() == 'subject' or sys.argv[i].lower() == 'haswords' or sys.argv[i].lower() == 'nowords' or sys.argv[i].lower() == 'musthaveattachment':
    if sys.argv[i].lower() == 'from':
      from_ = sys.argv[i+1]
      i = i + 2
      haveCondition = True
    elif sys.argv[i].lower() == 'to':
      to = sys.argv[i+1]
      i = i + 2
      haveCondition = True
    elif sys.argv[i].lower() == 'subject':
      subject = sys.argv[i+1]
      i = i + 2
      haveCondition = True
    elif sys.argv[i].lower() == 'haswords':
      has_the_word = sys.argv[i+1]
      i = i + 2
      haveCondition = True
    elif sys.argv[i].lower() == 'nowords':
      does_not_have_the_word = sys.argv[i+1]
      i = i + 2
      haveCondition = True
    elif sys.argv[i].lower() == 'musthaveattachment':
      has_attachment = True
      i = i + 1
      haveCondition = True
  if not haveCondition:
    showUsage()
    sys.exit(2)
  haveAction = False
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'label':
      label = sys.argv[i+1]
      i = i + 2
      haveAction = True
    elif sys.argv[i].lower() == 'markread':
      should_mark_as_read = True
      i = i + 1
      haveAction = True
    elif sys.argv[i].lower() == 'archive':
      should_archive = True
      i = i + 1
      haveAction = True
    elif sys.argv[i].lower() == 'star':
      should_star = True
      i = i + 1
      haveAction = True
    elif sys.argv[i].lower() == 'forward':
      forward_to = sys.argv[i+1]
      i = i + 2
      haveAction = True
    elif sys.argv[i].lower() == 'trash':
      should_trash = True
      i = i + 1
      haveAction = True
    elif sys.argv[i].lower() == 'neverspam':
      should_not_spam = True
      i = i + 1
      haveAction = True
    else:
      showUsage()
      sys.exit(2)
  if not haveAction:
    showUsage()
    sys.exit(2)
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Creating filter for %s (%s of %s)" % (user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.CreateFilter(username=user, from_=from_, to=to, subject=subject, has_the_word=has_the_word, does_not_have_the_word=does_not_have_the_word, has_attachment=has_attachment, label=label, should_mark_as_read=should_mark_as_read, should_archive=should_archive, should_star=should_star, forward_to=forward_to, should_trash=should_trash, should_not_spam=should_not_spam)
    i = i + 1

def doForward(users):
  checkTOS = True
  action = forward_to = None
  gotAction = gotForward = False
  if sys.argv[4] == 'on':
    enable = True
  elif sys.argv[4] == 'off':
    enable = False
  else:
    showUsage()
    sys.exit(2)
  i = 5
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'keep' or sys.argv[i].lower() == 'archive' or sys.argv[i].lower() == 'delete':
      action = sys.argv[i].upper()
      i = i + 1
      gotAction = True
    elif sys.argv[i].lower() == 'noconfirm':
      checkTOS = False
      i = i + 1
    elif sys.argv[i].find('@') != -1:
      forward_to = sys.argv[i]
      gotForward = True
      i = i + 1
    else:
      showUsage()
      sys.exit(2)
  if enable and (not gotAction or not gotForward):
    showUsage()
    sys.exit()
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Turning forward %s for %s, emails will be %s (%s of %s)" % (sys.argv[4], user, action, i, count)
    if checkTOS:
      if not hasAgreed2TOS(user):
        print ' Warning: Forwarding has been enabled but '+user+' has not logged into GMail to agree to the terms of service (captcha).  Forwarding will not work until they do.'
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.UpdateForwarding(username=user, enable=enable, action=action, forward_to=forward_to)
    i = i + 1

def getForward(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    while True:
      try:
        forward = emailsettings.GetForward(username=user)
        break
      except gdata.apps.service.AppsForYourDomainException, e:
        pass
    print "User %s:  Forward To:%s  Enabled:%s  Action:%s" % (user, forward['forwardTo'], forward['enable'], forward['action'])

def doSignature(users):
  signature = cgi.escape(sys.argv[4]).replace('\\n', '&#xA;')
  xmlsig = '''<?xml version="1.0" encoding="utf-8"?>
<atom:entry xmlns:atom="http://www.w3.org/2005/Atom" xmlns:apps="http://schemas.google.com/apps/2006">
    <apps:property name="signature" value="'''+signature+'''" />
</atom:entry>'''
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Setting Signature for %s (%s of %s)" % (user, i, count)
    #emailsettings.UpdateSignature(username=user, signature=signature)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    uri = 'https://apps-apis.google.com/a/feeds/emailsettings/2.0/'+emailsettings.domain+'/'+user+'/signature'
    emailsettings.Put(xmlsig, uri)
    i = i + 1

def getSignature(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    signature = emailsettings.GetSignature(username=user)
    print "User %s:  Signature: %s" % (user, signature['signature'])

def doWebClips(users):
  if sys.argv[4].lower() == 'on':
    enable = True
  elif sys.argv[4].lower() == 'off':
    enable = False
  else:
    showUsage()
    sys.exit(2)
  emailsettings = getEmailSettingsObject()
  count = len(users)
  i = 1
  for user in users:
    print "Turning Web Clips %s for %s (%s of %s)" % (sys.argv[4], user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    emailsettings.UpdateWebClipSettings(username=user, enable=enable)
    i = i + 1

def doVacation(users):
  subject = message = ''
  if sys.argv[4] == 'on':
    enable = 'true'
  elif sys.argv[4] == 'off':
    enable = 'false'
  else:
    showUsage()
    sys.exit(2)
  contacts_only = domain_only = 'false'
  start_date = end_date = None
  i = 5
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'subject':
      subject = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'message':
      message = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'contactsonly':
      contacts_only = 'true'
      i = i + 1
    elif sys.argv[i].lower() == 'domainonly':
      domain_only = 'true'
      i = i + 1
    elif sys.argv[i].lower() == 'startdate':
      start_date = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'enddate':
      end_date = sys.argv[i+1]
      i = i + 2  
    else:
      showUsage()
      sys.exit(2)
  i = 1
  count = len(users)
  emailsettings = getEmailSettingsObject()
  message = cgi.escape(message).replace('\\n', '&#xA;')
  vacxml = '''<?xml version="1.0" encoding="utf-8"?>
<atom:entry xmlns:atom="http://www.w3.org/2005/Atom" xmlns:apps="http://schemas.google.com/apps/2006">
    <apps:property name="enable" value="%s" />''' % enable
  if enable == 'true':
    vacxml += '''<apps:property name="subject" value="%s" />
    <apps:property name="message" value="%s" />
    <apps:property name="contactsOnly" value="%s" />
    <apps:property name="domainOnly" value="%s" />''' % (subject, message, contacts_only, domain_only)
    if start_date != None:
      vacxml += '<apps:property name="startDate" value="%s" />' % start_date
    if end_date != None:
      vacxml += '<apps:property name="endDate" value="%s" />' % end_date
  vacxml += '</atom:entry>'
  for user in users:
    print "Setting Vacation for %s (%s of %s)" % (user, i, count)
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain #make sure it's back at default domain
    uri = 'https://apps-apis.google.com/a/feeds/emailsettings/2.0/'+emailsettings.domain+'/'+user+'/vacation'
    emailsettings.Put(vacxml, uri)
    #emailsettings.UpdateVacation(username=user, enable=enable, subject=subject, message=message, contacts_only=contacts_only, domain_only=domain_only, start_date=start_date, end_date=end_date)
    i = i + 1

def getVacation(users):
  emailsettings = getEmailSettingsObject()
  for user in users:
    if user.find('@') > 0:
      emailsettings.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    else:
      emailsettings.domain = domain
    vacationsettings = emailsettings.GetVacation(username=user)
    print '''User %s
 Enabled: %s
 Contacts Only: %s
 Domain Only: %s
 Subject: %s
 Message: %s
 Start Date: %s
 End Date: %s
''' % (user, vacationsettings['enable'], vacationsettings['contactsOnly'], vacationsettings['domainOnly'], vacationsettings['subject'], vacationsettings['message'], vacationsettings['startDate'], vacationsettings['endDate'])


def doCreateUser():
  gotFirstName = gotLastName = gotPassword = False
  suspended = 'false'
  password_hash_function = quota_limit = change_password = None
  user_name = sys.argv[3]
  i = 4
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'firstname':
      given_name = sys.argv[i+1]
      gotFirstName = True
      i = i + 2
    elif sys.argv[i].lower() == 'lastname':
      family_name = sys.argv[i+1]
      gotLastName = True
      i = i + 2
    elif sys.argv[i].lower() == 'password':
      password = sys.argv[i+1]
      gotPassword = True
      i = i + 2
    elif sys.argv[i].lower() == 'suspended':
      suspended='true'
      i = i + 1
    elif sys.argv[i].lower() == 'sha' or sys.argv[i].lower() == 'sha1' or sys.argv[i].lower() == 'sha-1':
      password_hash_function = 'SHA-1'
      i = i + 1
    elif sys.argv[i].lower() == 'md5':
      password_hash_function = 'MD5'
      i = i + 1
    elif sys.argv[i].lower() == 'quota':
      quota_limit = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'changepassword':
      change_password = 'true'
      i = i + 1
    else:
      showUsage()
      sys.exit(2)
  if not (gotFirstName and gotLastName and gotPassword):
    showUsage()
    sys.exit(2)
  if password_hash_function == None:
    newhash = sha1()
    newhash.update(password)
    password = newhash.hexdigest()
    password_hash_function = 'SHA-1'
  print "Creating account for %s" % user_name
  apps = getAppsObject()
  if user_name.find('@') > 0:
    apps.domain = user_name[user_name.find('@')+1:]
    user_name = user_name[:user_name.find('@')]
  try:
    apps.CreateUser(user_name=user_name, family_name=family_name, given_name=given_name, password=password, suspended=suspended, quota_limit=quota_limit, password_hash_function=password_hash_function, change_password=change_password)
  except gdata.apps.service.AppsForYourDomainException, e:
    xmlerror = xml.dom.minidom.parseString(e[0]['body'])
    detailedreason = xmlerror.getElementsByTagName('error')[0].getAttribute('reason')
    print 'Error: %s - %s' % (e[0]['reason'], detailedreason)
    exit(22)

def doCreateGroup():
  group = sys.argv[3]
  got_name = got_description = got_permission = False
  i = 4
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'name':
      group_name = sys.argv[i+1]
      got_name = True
      i = i + 2
    elif sys.argv[i].lower() == 'description':
      group_description = sys.argv[i+1]
      got_description = True
      i = i + 2
    elif sys.argv[i].lower() == 'permission':
      group_permission = sys.argv[i+1]
      if group_permission.lower() == 'owner':
        group_permission = 'Owner'
      elif group_permission.lower() == 'member':
        group_permission = 'Member'
      elif group_permission.lower() == 'domain':
        group_permission = 'Domain'
      elif group_permission.lower() == 'anyone':
        group_permission = 'Anyone'
      else:
        showUsage()
        sys.exit(2)
      got_permission = True
      i = i + 2
  if not got_name or not got_description or not got_permission:
    showUsage()
    sys.exit(2)
  groupObj = getGroupsObject()
  result = groupObj.CreateGroup(group, group_name, group_description, group_permission)

def doCreateNickName():
  alias_email = sys.argv[3]
  if sys.argv[4].lower() != 'user':
    showUsage()
    sys.exit(2)
  user_email = sys.argv[5]
  multi = getMultiDomainObject()
  if alias_email.find('@') == -1:
    alias_email = '%s@%s' % (alias_email, domain)
  if user_email.find('@') == -1:
    user_email = '%s@%s' % (user_email, domain)
  print 'Creating alias %s for user %s' % (alias_email, user_email)
  multi.CreateAlias(user_email=user_email, alias_email=alias_email)

def doCreateOrg():
  name = sys.argv[3]
  description = ''
  parent_org_unit_path = '/'
  block_inheritance = False
  i = 4
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'description':
      description = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'parent':
      parent_org_unit_path = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'noinherit':
      block_inheritance = True
      i = i + 1
  org = getOrgObject()
  org.CreateOrganizationUnit(name=name, description=description, parent_org_unit_path=parent_org_unit_path, block_inheritance=block_inheritance)

def doCreateResource():
  id = sys.argv[3]
  common_name = sys.argv[4]
  description = None
  type = None
  i = 5
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'description':
      description = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'type':
      type = sys.argv[i+1]
      i = i + 2
  rescal = getResCalObject()
  rescal.CreateResourceCalendar(id=id, common_name=common_name, description=description, type=type)

def doUpdateUser():
  gotPassword = isMD5 = isSHA1 = False
  given_name = family_name = password = admin = suspended = ip_whitelisted = hash_function_name = change_password = None
  supplied_user = sys.argv[3]
  i = 4
  use_multidomain = False
  use_prov = False
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'firstname':
      use_prov = True
      given_name = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'lastname':
      use_prov = True
      family_name = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'username':
      new_username = sys.argv[i+1]
      use_multidomain = True
      i = i + 2
    elif sys.argv[i].lower() == 'password':
      use_prov = True
      password = sys.argv[i+1]
      i = i + 2
      gotPassword = True
    elif sys.argv[i].lower() == 'admin':
      use_prov = True
      if sys.argv[i+1].lower() == 'on':
        admin = 'true'
      elif sys.argv[i+1].lower() == 'off':
        admin = 'false'
      i = i + 2
    elif sys.argv[i].lower() == 'suspended':
      use_prov = True
      if sys.argv[i+1].lower() == 'on':
        suspended = 'true'
      elif sys.argv[i+1].lower() == 'off':
        suspended = 'false'
      i = i + 2
    elif sys.argv[i].lower() == 'ipwhitelisted':
      use_prov = True
      if sys.argv[i+1].lower() == 'on':
        ip_whitelisted = 'true'
      elif sys.argv[i+1].lower() == 'off':
        ip_whitelisted = 'false'
      i = i + 2
    elif sys.argv[i].lower() == 'sha1' or sys.argv[i].lower() == 'sha1' or sys.argv[i].lower() == 'sha-1':
      use_prov = True
      hash_function_name = 'SHA-1'
      i = i + 1
      isSHA1 = True
    elif sys.argv[i].lower() == 'md5':
      use_prov = True
      hash_function_name = 'MD5'
      i = i + 1
      isMD5 = True
    elif sys.argv[i].lower() == 'changepassword':
      use_prov = True
      if sys.argv[i+1].lower() == 'on':
        change_password = 'true'
      elif sys.argv[i+1].lower() == 'off':
        change_password = 'false'
      i = i + 2
    else:
      showUsage()
      sys.exit(2)
  
  if gotPassword and not (isSHA1 or isMD5):
    newhash = sha1()
    newhash.update(password)
    password = newhash.hexdigest()
    hash_function_name = 'SHA-1'
  if use_prov:
    apps = getAppsObject()
    if supplied_user.find('@') > 0:
      apps.domain = supplied_user[supplied_user.find('@')+1:]
      user_name = supplied_user[:supplied_user.find('@')]
    else:
      user_name = supplied_user
    try:
      user = apps.RetrieveUser(user_name)
    except gdata.apps.service.AppsForYourDomainException, e:
      if e.reason == 'EntityDoesNotExist':
        print "ERROR: "+user_name+" is not an existing user."
      else:
        print 'ERROR: '+e.reason+' Status Code: '+e.status
      sys.exit(1)
    if given_name != None:
      user.name.given_name = given_name
    if family_name != None:
      user.name.family_name = family_name
    if password != None:
      user.login.password = password
    if admin != None:
      user.login.admin = admin
    if suspended != None:
      user.login.suspended = suspended
    if ip_whitelisted != None:
      user.login.ip_whitelisted = ip_whitelisted
    if hash_function_name != None:
      user.login.hash_function_name = hash_function_name
    if change_password != None:
      user.login.change_password = change_password
    try:
      apps.UpdateUser(user_name, user)
    except gdata.apps.service.AppsForYourDomainException, e:
      print e
      if e.reason == 'EntityExists':
        print "ERROR: "+user.login.user_name+" is an existing user, group or alias. Please delete the existing entity with this name before renaming "+user_name
      elif e.reason == 'UserDeletedRecently':
        print "ERROR: "+user.login.user_name+" was a user account recently deleted. You'll need to wait 5 days before you can reuse this name."
      else:
        print "ERROR: "+e.reason
      sys.exit(1)
  if use_multidomain:
    multi = getMultiDomainObject()
    if supplied_user.find('@') == -1:
      user_email = supplied_user + '@' + multi.domain
    else:
      user_email = supplied_user
    if new_username.find('@') == -1:
      new_email = new_username + '@' + multi.domain
    else:
      new_email = new_username
    multi.RenameUser(old_email=user_email, new_email=new_email)

def doUpdateGroup():
  groupObj = getGroupsObject()
  group = sys.argv[3]
  if group.find('@') == -1:
    group = group+'@'+domain
  if sys.argv[4].lower() == 'add':
    if sys.argv[5].lower() == 'owner':
      userType = 'Owner'
    elif sys.argv[5].lower() == 'member':
      userType = 'Member'
    user = sys.argv[6]
    if user.find('@') == -1:
      email = user+'@'+domain
    else:
      email = user
    if userType == 'Member':
      result = groupObj.AddMemberToGroup(email, group)
      result2 = groupObj.RemoveOwnerFromGroup(email, group)
    elif userType == 'Owner':
      result = groupObj.AddMemberToGroup(email, group)
      result2 = groupObj.AddOwnerToGroup(email, group)
  elif sys.argv[4].lower() == 'remove':
    user = sys.argv[5]
    if user.find('@') == -1:
      email = user+'@'+domain
    else:
      email = user
    result = groupObj.RemoveMemberFromGroup(email, group)
  else:
    i = 4
    use_prov_api = True
    if not sys.argv[i].lower() == 'settings':
      groupInfo = groupObj.RetrieveGroup(group)
      while i < len(sys.argv):
        if sys.argv[i].lower() == 'name':
          groupInfo['groupName'] = sys.argv[i+1]
          i = i + 2        
        elif sys.argv[i].lower() == 'description':
          groupInfo['description'] = sys.argv[i+1]
          i = i + 2
        elif sys.argv[i].lower() == 'permission':
          if sys.argv[i+1].lower() == 'owner':
            groupInfo['emailPermission'] = 'Owner'
          elif sys.argv[i+1].lower() == 'member':
            groupInfo['emailPermission'] = 'Member'
          elif sys.argv[i+1].lower() == 'domain':
            groupInfo['emailPermission'] = 'Domain'
          elif sys.argv[i+1].lower() == 'anyone':
            groupInfo['emailPermission'] = 'Anyone'
          i = i + 2
    else:
      use_prov_api = False
      i = i + 1
    if use_prov_api:
      result = groupObj.UpdateGroup(group, groupInfo['groupName'], groupInfo['description'], groupInfo['emailPermission'])
    else:
      allow_external_members = allow_google_communication = allow_web_posting = archive_only = custom_reply_to = default_message_deny_notification_text = description = is_archived = max_message_bytes = members_can_post_as_the_group = message_display_font = message_moderation_level = name = primary_language = reply_to = send_message_deny_notification = show_in_group_directory = who_can_invite =  who_can_join = who_can_post_message = who_can_view_group = who_can_view_membership = None
      while i < len(sys.argv):
        if sys.argv[i].lower() == 'allow_external_members':
          allow_external_members = sys.argv[i+1].lower()
          if allow_external_members != 'true' and allow_external_members != 'false':
            print 'Error: Value for allow_external_members must be true or false. Got %s' % allow_external_members
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'message_moderation_level':
          message_moderation_level = sys.argv[i+1].upper()
          if message_moderation_level != 'MODERATE_ALL_MESSAGES' and message_moderation_level != 'MODERATE_NEW_MEMBERS' and message_moderation_level != 'MODERATE_NONE' and message_moderation_level != 'MODERATE_NON_MEMBERS':
            print 'Error: Value for message_moderation_level must be moderate_all_message, moderate_new_members, moderate_none or moderate_non_members. Got %s' % allow_external_members
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'name':
          name = sys.argv[i+1]
          i = i + 2
        elif sys.argv[i].lower() == 'primary_language':
          primary_language = sys.argv[i+1]
          i = i + 2
        elif sys.argv[i].lower() == 'reply_to':
          reply_to = sys.argv[i+1].upper()
          if reply_to != 'REPLY_TO_CUSTOM' and reply_to != 'REPLY_TO_IGNORE' and reply_to != 'REPLY_TO_LIST' and reply_to != 'REPLY_TO_MANAGERS' and reply_to != 'REPLY_TO_OWNER' and reply_to != 'REPLY_TO_SENDER':
            print 'Error: Value for reply_to must be reply_to_custom, reply_to_ignore, reply_to_list, reply_to_managers, reply_to_owner or reply_to_sender. Got %s' % reply_to
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'send_message_deny_notification':
          send_message_deny_notification = sys.argv[i+1].lower()
          if send_message_deny_notification != 'true' and send_message_deny_notification != 'false':
            print 'Error: Value for send_message_deny_notification must be true or false. Got %s' % send_message_deny_notification
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'show_in_groups_directory' or sys.argv[i].lower() == 'show_in_group_directory':
          show_in_group_directory = sys.argv[i+1].lower()
          if show_in_group_directory != 'true' and show_in_group_directory != 'false':
            print 'Error: Value for show_in_group_directory must be true or false. Got %s' % show_in_group_directory
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'who_can_invite':
          who_can_invite = sys.argv[i+1].upper()
          if who_can_invite != 'ALL_MANAGERS_CAN_INVITE' and who_can_invite != 'ALL_MEMBERS_CAN_INVITE':
            print 'Error: Value for who_can_invite must be all_managers_can_invite or all_members_can_invite. Got %s' % who_can_invite
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'who_can_join':
          who_can_join = sys.argv[i+1].upper()
          if who_can_join != 'ALL_IN_DOMAIN_CAN_JOIN' and who_can_join != 'ANYONE_CAN_JOIN' and who_can_join != 'CAN_REQUEST_TO_JOIN' and who_can_join != 'INVITED_CAN_JOIN':
            print 'Error: Value for who_can_join must be all_in_domain_can_join, anyone_can_join, can_request_to_join or invited_can_join. Got %s' % who_can_join
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'who_can_post_message':
          who_can_post_message = sys.argv[i+1].upper()
          if who_can_post_message != 'ALL_IN_DOMAIN_CAN_POST' and who_can_post_message != 'ALL_MANAGERS_CAN_POST' and who_can_post_message != 'ALL_MEMBERS_CAN_POST' and who_can_post_message != 'ANYONE_CAN_POST' and who_can_post_message != 'NONE_CAN_POST':
            print 'Error: Value for who_can_post_message must be all_in_domain_can_post, all_managers_can_post, all_members_can_post, anyone_can_post or none_can_post. Got %s' % who_can_post_message
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'who_can_view_group':
          who_can_view_group = sys.argv[i+1].upper()
          if who_can_view_group != 'ALL_IN_DOMAIN_CAN_VIEW' and who_can_view_group != 'ALL_MANAGERS_CAN_VIEW' and who_can_view_group != 'ALL_MEMBERS_CAN_VIEW' and who_can_view_group != 'ANYONE_CAN_VIEW':
            print 'Error: Value for who_can_view_group must be all_in_domain_can_view, all_managers_can_view, all_members_can_view or anyone_can_view. Got %s' % who_can_view_group
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'who_can_view_membership':
          who_can_view_membership = sys.argv[i+1].upper()
          if who_can_view_membership != 'ALL_IN_DOMAIN_CAN_VIEW' and who_can_view_membership != 'ALL_MANAGERS_CAN_VIEW' and who_can_view_membership != 'ALL_MEMBERS_CAN_VIEW' and who_can_view_membership != 'ANYONE_CAN_VIEW':
            print 'Error: Value for who_can_view_membership must be all_in_domain_can_view, all_managers_can_view, all_members_can_view or anyone_can_view. Got %s' % who_can_view_membership
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'allow_google_communication':
          allow_google_communication = sys.argv[i+1].lower()
          if allow_google_communication != 'true' and allow_google_communication != 'false':
            print 'Error: Value for allow_google_communication must be true or false. Got %s' % allow_google_communication
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'allow_web_posting':
          allow_web_posting = sys.argv[i+1].lower()
          if allow_web_posting != 'true' and allow_web_posting != 'false':
            print 'Error: Value for allow_web_posting must be true or false. Got %s' % allow_web_posting
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'archive_only':
          archive_only = sys.argv[i+1].lower()
          if archive_only != 'true' and archive_only != 'false':
            print 'Error: Value for archive_only must be true or false. Got %s' % archive_only
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'custom_reply_to':
          custom_reply_to = sys.argv[i+1]
          i = i + 2
        elif sys.argv[i].lower() == 'default_message_deny_notification_text':
          default_message_deny_notification_text = sys.argv[i+1]
          i = i + 2
        elif sys.argv[i].lower() == 'description':
          description = sys.argv[i+1]
          i = i + 2
        elif sys.argv[i].lower() == 'is_archived':
          is_archived = sys.argv[i+1].lower()
          if is_archived != 'true' and is_archived != 'false':
            print 'Error: Value for is_archived must be true or false. Got %s' % is_archived
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'max_message_bytes':
          max_message_bytes = sys.argv[i+1]
          try:
            if max_message_bytes[-1:].upper() == 'M':
              max_message_bytes = str(int(max_message_bytes[:-1]) * 1024 * 1024)
            elif max_message_bytes[-1:].upper() == 'K':
              max_message_bytes = str(int(max_message_bytes[:-1]) * 1024)
            elif max_message_bytes[-1].upper() == 'B':
              max_message_bytes = str(int(max_message_bytes[:-1]))
            else:
              max_message_bytes = str(int(max_message_bytes))
          except ValueError:
            print 'Error: max_message_bytes must be a number ending with M (megabytes), K (kilobytes) or nothing (bytes). Got %s' % max_message_bytes
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'members_can_post_as_the_group':
          members_can_post_as_the_group = sys.argv[i+1].lower()
          if members_can_post_as_the_group != 'true' and members_can_post_as_the_group != 'false':
            print 'Error: Value for members_can_post_as_the_group must be true or false. Got %s' % members_can_post_as_the_group
            sys.exit(9)
          i = i + 2
        elif sys.argv[i].lower() == 'message_display_font':
          message_display_font = sys.argv[i+1].upper()
          if message_display_font != 'DEFAULT_FONT' and message_display_font != 'FIXED_WIDTH_FONT':
            print 'Error: Value for message_display_font must be default_font or fixed_width_font. Got %s' % message_display_font
            sys.exit(9)
          i = i + 2
        else:
          print 'Error: %s is not a valid setting for groups' % sys.argv[i]
          sys.exit(10)
      gs = getGroupSettingsObject()
      results = gs.UpdateGroupSettings(group_email=group, allow_external_members=allow_external_members,
    allow_google_communication=allow_google_communication, allow_web_posting=allow_web_posting, archive_only=archive_only, custom_reply_to=custom_reply_to,
    default_message_deny_notification_text=default_message_deny_notification_text, description=description, is_archived=is_archived, max_message_bytes=max_message_bytes,
    members_can_post_as_the_group=members_can_post_as_the_group, message_display_font=message_display_font, message_moderation_level=message_moderation_level, name=name,
    primary_language=primary_language, reply_to=reply_to, send_message_deny_notification=send_message_deny_notification, show_in_group_directory=show_in_group_directory,
    who_can_invite=who_can_invite, who_can_join=who_can_join, who_can_post_message=who_can_post_message, who_can_view_group=who_can_view_group,
    who_can_view_membership=who_can_view_membership)

def doUpdateNickName():
  alias_email = sys.argv[3]
  if sys.argv[4].lower() != 'user':
    showUsage()
    sys.exit(2)
  user_email = sys.argv[5]
  multi = getMultiDomainObject()
  if alias_email.find('@') == -1:
    alias_email = '%s@%s' % (alias_email, domain)
  if user_email.find('@') == -1:
    user_email = '%s@%s' % (user_email, domain)
  multi.DeleteAlias(alias_email=alias_email)
  multi.CreateAlias(user_email=user_email, alias_email=alias_email)

def doUpdateResourceCalendar():
  id = sys.argv[3]
  common_name = None
  description = None
  type = None
  i = 4
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'name':
      common_name = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'description':
      description = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'type':
      type = sys.argv[i+1]
      i = i + 2
  rescal = getResCalObject()
  rescal.UpdateResourceCalendar(id=id, common_name=common_name, description=description, type=type)

def doUpdateOrg():
  name = sys.argv[3]
  new_name = None
  description = None
  parent_org_unit_path = None
  block_inheritance = None
  users_to_move = []
  org = getOrgObject()
  users = []
  apps = getAppsObject()
  i = 4
  if sys.argv[4].lower() == 'add':
    users = sys.argv[5].split(' ')
    i = 6
  elif sys.argv[4].lower() == 'fileadd' or sys.argv[4].lower() == 'addfile':
    users = []
    filename = sys.argv[5]
    usernames = csv.reader(open(filename, 'rb'))
    for row in usernames:
      users.append(row.pop())
    i = 6
  elif sys.argv[4].lower() == 'groupadd'or sys.argv[4].lower() == 'addgroup':
    groupsObj = getGroupsObject()
    group = sys.argv[5]
    members = groupsObj.RetrieveAllMembers(group)
    for member in members:
      users.append(member['memberId'])
    i = 6
  elif sys.argv[4].lower() == 'addnotingroup':
    print 'Retrieving all users in Google Apps Organization (may take some time)'
    allorgusersresults = org.RetrieveAllOrganizationUsers()
    print 'Retrieved %s users' % len(allorgusersresults)
    for auser in allorgusersresults:
      users.append(auser['orgUserEmail'])
    group = sys.argv[5]
    print 'Retrieving all members of %s group (may take some time)' % group
    groupsObj = getGroupsObject()
    members = groupsObj.RetrieveAllMembers(group)
    for member in members:
      try:
        users.remove(member['memberId'])
      except ValueError:
        continue
    i = 6
  totalusers = len(users)
  if totalusers > 50:
    print "got %s users to be added" % totalusers
    alreadyInOU = org.RetrieveAllOrganizationUnitUsers(name)
    alreadyCount = 0
    for user in alreadyInOU:
      try:
        users.remove(user['orgUserEmail'])
        alreadyCount = alreadyCount + 1
      except ValueError:
        continue
    if alreadyCount > 0:
      print "%s users were already in org %s and won't be re-added" % (alreadyCount, name)
      totalusers = len(users)
  currentrange = 1
  while len(users) > 20:
    reason = invalidInput = None
    while len(users_to_move) <= 20:
      users_to_move.append(users.pop())
    print "Adding users %s to %s out of %s total to org %s" % (currentrange, currentrange+19, totalusers, name)
    try:
      org.UpdateOrganizationUnit(old_name=name, users_to_move=users_to_move)
      currentrange = currentrange + 20
      users_to_move = []
      continue
    except gdata.apps.service.AppsForYourDomainException, e:
      reason = e.reason
      invalidInput = e.invalidInput
      if reason == 'EntityDoesNotExist' and invalidInput == 'orgUnitUsersToMove':
        #find out which user is not in the domain
        remove_users = []
        for user in users_to_move:
          try:
            if user.find('@') != -1:
              apps.domain = user[user.find('@')+1:]
              username = user[0:user.find('@')]
            else:
              apps.domain = domain
              username = user
            apps.RetrieveUser(username)
          except gdata.apps.service.AppsForYourDomainException, e:
            if e.message['reason'][:59] == 'You are not authorized to perform operations on the domain ' or e.message['reason'] == 'Invalid domain.':
              remove_users.append(user)
              print 'not adding external user '+user
            elif e.reason == 'EntityDoesNotExist':
              remove_users.append(user)
              print 'not adding non-existant user '+user
        for user in remove_users:
          users_to_move.remove(user)
        if len(users_to_move) > 0:
          org.UpdateOrganizationUnit(old_name=name, users_to_move=users_to_move)
        currentrange = currentrange + 20
        users_to_move = []
  while len(users) > 0:
    users_to_move.append(users.pop())
  if len(users_to_move) < 1:
    users_to_move = None
  else:
    print 'Adding users %s to %s and making other updates to org %s' % (currentrange, totalusers, name)
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'name':
      new_name = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'description':
      description = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'parent':
      parent_org_unit_path = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'noinherit':
      block_inheritance = True
      i = i + 1
    elif sys.argv[i].lower() == 'inherit':
      block_inheritance = False
      i = i + 1
  try:
    reason = invalidInput = None
    org.UpdateOrganizationUnit(old_name=name, new_name=new_name, description=description, parent_org_unit_path=parent_org_unit_path, block_inheritance=block_inheritance, users_to_move=users_to_move)
    exit(0)
  except gdata.apps.service.AppsForYourDomainException, e:
    reason = e.reason
    invalidInput = e.invalidInput
  if reason == 'EntityDoesNotExist' and invalidInput == 'orgUnitUsersToMove':
    #find out which users aren't local or are invalid
    remove_users = []
    for user in users_to_move:
      if user.find('@') != -1:
        apps.domain = user[user.find('@')+1:]
        username = user[0:user.find('@')]
      else:
        apps.domain = domain
        username = user
      try:
        apps.RetrieveUser(username)
      except gdata.apps.service.AppsForYourDomainException, e:
        if e.message['reason'][:59] == 'You are not authorized to perform operations on the domain ' or e.message['reason'] == 'Invalid domain.':
          remove_users.append(user)
          print 'not adding external user '+user
        elif e.reason == 'EntityDoesNotExist':
          remove_users.append(user)
          print 'not adding non-existant user '+user
    for user in remove_users:
      users_to_move.remove(user)
    if len(users_to_move) < 1:
      users_to_move = None
    org.UpdateOrganizationUnit(old_name=name, new_name=new_name, description=description, parent_org_unit_path=parent_org_unit_path, block_inheritance=block_inheritance, users_to_move=users_to_move)

def doGetUserInfo():
  user_name = sys.argv[3]
  apps = getAppsObject()
  getAliases = getGroups = getOrg = True
  i = 4
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'noaliases':
      getAliases = False
      i = i + 1
    elif sys.argv[i].lower() == 'nogroups':
      getGroups = False
      i = i + 1
    elif sys.argv[i].lower() == 'noorg':
      getOrg = False
      i = i + 1
  if user_name.find('@') > 0:
    apps.domain = user_name[user_name.find('@')+1:]
    user_name = user_name[:user_name.find('@')]
  user = apps.RetrieveUser(user_name)
  print 'User: %s' % user.login.user_name + '@' + apps.domain
  print 'First Name: %s' % user.name.given_name
  print 'Last Name: %s' % user.name.family_name
  print 'Is an admin: %s' % user.login.admin
  print 'Has agreed to terms: %s' % user.login.agreed_to_terms
  print 'IP Whitelisted: %s' % user.login.ip_whitelisted
  print 'Account Suspended: %s' % user.login.suspended
  print 'Must Change Password: %s' % user.login.change_password
  print 'Quota: %s' % user.quota.limit
  if getOrg:
    orgObj = getOrgObject()
    try:
      user_org = orgObj.RetrieveUserOrganization('%s@%s' % (user_name, apps.domain))
      print 'Organization: %s' % user_org['orgUnitPath']
    except gdata.apps.service.AppsForYourDomainException, e:
      print e
  if getAliases:
    multi = getMultiDomainObject()
    print 'Email Aliases (Nicknames):'
    nicknames = multi.GetUserAliases(user_name+'@'+apps.domain)
    for nick in nicknames:
      print '  ' + nick['aliasEmail']
  if getGroups:
    groupObj = getGroupsObject()
    groupObj.domain = apps.domain
    groups = groupObj.RetrieveGroups('%s@%s' % (user_name, apps.domain))
    print 'Groups:'
    for group in groups:
      if group['directMember'] == 'true':
        directIndirect = 'direct'
      else:
        directIndirect = 'indirect'
      print '  ' + group['groupName'] + ' <' + group['groupId'] + '> (' + directIndirect + ' member)'
   
def doGetGroupInfo():
  group_name = sys.argv[3]
  show_group_settings = False
  try:
    if sys.argv[4].lower() == 'settings':
      show_group_settings = True
  except IndexError:
    pass
  if not show_group_settings:
    groupObj = getGroupsObject()
    if group_name.find('@') == -1:
      group_name = group_name+'@'+domain
    group = groupObj.RetrieveGroup(group_name)
    print 'Group Name: ',group['groupName']
    try:
      print 'Email Permission: ',group['emailPermission']
    except KeyError:
      print 'Email Permission: Unknown'
    print 'Group ID: ',group['groupId']
    print 'Description: ',group['description']
    owners = groupObj.RetrieveAllOwners(group_name)
    owner_list = []
    for owner in owners:
	  owner_list.append(owner['email'])
	  print 'Owner: %s' % owner['email']
    members = groupObj.RetrieveAllMembers(group_name)
    users = []
    for member in members:
      users.append(member['memberId'])
    for user in users:
      if user in owner_list:
        continue
      else:
        print 'Member:',user
  else: # show group settings
    gs = getGroupSettingsObject()
    if group_name.find('@') == -1:
      group_name = group_name+'@'+gs.domain
    try:
      settings = gs.RetrieveGroupSettings(group_name)
    except gdata.service.RequestError, e:
      print e
      exit(8)
    print ''
    print 'Group Settings:'
    for setting in settings:
      setting_key = re.sub(r'([A-Z])', r'_\1', setting.keys()[0]).lower()
      setting_value = setting.values()[0]
      if setting_value == None:
        setting_value = ''
      setting_value = setting_value
      print ' %s: %s' % (setting_key, setting_value)

def doGetNickNameInfo():
  alias_email = sys.argv[3]
  multi = getMultiDomainObject()
  if alias_email.find('@') == -1:
    alias_email = '%s@%s' % (alias_email, domain)
  result = multi.RetrieveAlias(alias_email=alias_email)
  print ' Alias Email: '+result['aliasEmail']
  print ' User Email: '+result['userEmail']

def doGetResourceCalendarInfo():
  id = sys.argv[3]
  rescal = getResCalObject()
  result = rescal.RetrieveResourceCalendar(id)
  print ' Resource ID: '+result['resourceId']
  print ' Common Name: '+result['resourceCommonName']
  print ' Email: '+result['resourceEmail']
  try:
    print ' Type: '+result['resourceType']
  except KeyError:
    print ' Type: '
  try:
    print ' Description: '+result['resourceDescription']
  except KeyError:
    print ' Description: '

def doGetOrgInfo():
  name = sys.argv[3]
  org = getOrgObject()
  result = org.RetrieveOrganizationUnit(name)
  print 'Organization Unit: '+result['name']
  if result['description'] != None:
    print 'Description: '+result['description']
  else:
    print 'Description: '
  if result['parentOrgUnitPath'] != None:
    print 'Parent Org: '+result['parentOrgUnitPath']
  else:
    print 'Parent Org: /'
  print 'Block Inheritance: '+result['blockInheritance']
  result2 = org.RetrieveAllOrganizationUnitUsers(name)
  print 'Users: '
  for user in result2:
    print ' '+user['orgUserEmail']

def doUpdateDomain():
  adminObj = getAdminSettingsObject()
  command = sys.argv[3].lower()
  if command == 'language':
    language = sys.argv[4]
    adminObj.UpdateDefaultLanguage(language)
  elif command == 'name':
    name = sys.argv[4]
    adminObj.UpdateOrganizationName(name)
  elif command == 'admin_secondary_email':
    admin_secondary_email = sys.argv[4]
    if admin_secondary_email.find('@') == -1:
      print 'Error: %s is not a valid email address.' % admin_secondary_email
      sys.exit(11)
    adminObj.UpdateAdminSecondaryEmail(admin_secondary_email)
  elif command == 'logo':
    logo_file = sys.argv[4]
    try:
      fp = open(logo_file, 'rb')
      logo_image = fp.read()
      fp.close()
    except IOError:
      print 'Error: can\'t open file %s' % logo_file
      sys.exit(11)
    adminObj.UpdateDomainLogo(logo_image)
  elif command == 'cname_verify':
    result = adminObj.UpdateCNAMEVerificationStatus('true')
    print 'Record Name: %s' % result['recordName']
    print 'Verification Method: %s' % result['verificationMethod']
    print 'Verified: %s' % result['verified']
  elif command == 'mx_verify':
    result = adminObj.UpdateMXVerificationStatus('true')
    print 'Verification Method: %s' % result['verificationMethod']
    print 'Verified: %s' % result['verified']
  elif command == 'sso_settings':
    enableSSO = samlSignonUri = samlLogoutUri = changePasswordUri = ssoWhitelist = useDomainSpecificIssuer = None
    i = 4
    while i < len(sys.argv):
      if sys.argv[i].lower() == 'enabled':
        if sys.argv[i+1].lower() == 'true':
          enableSSO = True
        elif sys.argv[i+1].lower() == 'false':
          enableSSO = False
        else:
          print 'Error: value for enabled must be true or false, got %s' % sys.argv[i+1]
          exit(9)
        i = i + 2
      elif sys.argv[i].lower() == 'sign_on_uri':
        samlSignonUri = sys.argv[i+1]
        i = i + 2
      elif sys.argv[i].lower() == 'sign_out_uri':
        samlLogoutUri = sys.argv[i+1]
        i = i + 2
      elif sys.argv[i].lower() == 'password_uri':
        changePasswordUri = sys.argv[i+1]
        i = i + 2
      elif sys.argv[i].lower() == 'whitelist':
        ssoWhitelist = sys.argv[i+1]
        i = i + 2
      elif sys.argv[i].lower() == 'use_domain_specific_issuer':
        if sys.argv[i+1].lower() == 'true':
          useDomainSpecificIssuer = True
        elif sys.argv[i+1].lower() == 'false':
          useDomainSpecificIssuer = False
        else:
          print 'Error: value for use_domain_specific_issuer must be true or false, got %s' % sys.argv[i+1]
          sys.exit(9)
        i = i + 2 
      else:
        print 'Error: unknown option for "gam update domain sso_settings...": %s' % sys.argv[i]
        sys.exit(9)
    adminObj.UpdateSSOSettings(enableSSO=enableSSO, samlSignonUri=samlSignonUri, samlLogoutUri=samlLogoutUri, changePasswordUri=changePasswordUri, ssoWhitelist=ssoWhitelist, useDomainSpecificIssuer=useDomainSpecificIssuer)
  elif command == 'sso_key':
    key_file = sys.argv[4]
    try:
      fp = open(key_file, 'rb')
      key_data = fp.read()
      fp.close()
    except IOError:
      print 'Error: can\'t open file %s' % logo_file
      sys.exit(11)
    adminObj.UpdateSSOKey(key_data)
  elif command == 'user_migrations':
    value = sys.argv[4].lower()
    if value != 'true' and value != 'false':
      print 'Error: value for user_migrations must be true or false, got %s' % sys.argv[4]
      sys.exit(9)
    result = adminObj.UpdateUserMigrationStatus(value)
  elif command == 'outbound_gateway':
    gateway = sys.argv[4]
    mode = sys.argv[6].upper()
    try:
      result = adminObj.UpdateOutboundGatewaySettings(gateway, mode)
    except TypeError:
      pass
  elif command == 'email_route':
    i = 4
    while i < len(sys.argv):
      if sys.argv[i].lower() == 'destination':
        destination = sys.argv[i+1]
        i = i + 2
      elif sys.argv[i].lower() == 'rewrite_to':
        rewrite_to = sys.argv[i+1].lower()
        if rewrite_to == 'true':
          rewrite_to = True
        elif rewrite_to == 'false':
          rewrite_to = False
        else: 
          print 'Error: value for rewrite_to must be true or false, got %s' % sys.argv[i+1]
          sys.exit(9)
        i = i + 2
      elif sys.argv[i].lower() == 'enabled':
        enabled = sys.argv[i+1].lower()
        if enabled == 'true':
          enabled = True
        elif enabled == 'false':
          enabled = False
        else:
          print 'Error: value for enabled must be true or false, got %s' % sys.argv[i+1]
          sys.exit(9)
        i = i + 2
      elif sys.argv[i].lower() == 'bounce_notifications':
        bounce_notifications = sys.argv[i+1].lower()
        if bounce_notifications == 'true':
          bounce_notifications = True
        elif bounce_notifications == 'false':
          bounce_notifications = False
        else:
          print 'Error: value for bounce_notifications must be true or false, got %s' % sys.argv[i+1]
          sys.exit(9)
        i = i + 2
      elif sys.argv[i].lower() == 'account_handling':
        account_handling = sys.argv[i+1].lower()
        if account_handling == 'all_accounts':
          account_handling = 'allAccounts'
        elif account_handling == 'provisioned_accounts':
          account_handling = 'provisionedAccounts'
        elif account_handling == 'unknown_accounts':
          account_handling = 'unknownAccounts'
        else:
          print 'Error: value for account_handling must be all_accounts, provisioned_account or unknown_accounts. Got %s' % sys.argv[i+1]
          sys.exit(9)
        i = i + 2
      else:
        print 'Error: invalid setting for "gam update domain email_route..."'
        sys.exit(10)
    response = adminObj.AddEmailRoute(routeDestination=destination, routeRewriteTo=rewrite_to, routeEnabled=enabled, bounceNotifications=bounce_notifications, accountHandling=account_handling)
  else:
    print 'Error: that is not a valid "gam update domain" command'

def doGetDomainInfo():
  adminObj = getAdminSettingsObject()
  if len(sys.argv) > 4 and sys.argv[3].lower() == 'logo':
    target_file = sys.argv[4]
    logo_image = adminObj.GetDomainLogo()
    try:
      fp = open(target_file, 'wb')
      fp.write(logo_image)
      fp.close()
    except IOError:
      print 'Error: can\'t open file %s for writing' % target_file
      sys.exit(11)
    sys.exit(0)
  #pause 1 sec inbetween calls to prevent quota warning
  print 'Google Apps Domain: ', adminObj.domain
  time.sleep(1)
  print 'Default Language: ', adminObj.GetDefaultLanguage()
  time.sleep(1)
  print 'Organization Name: ', adminObj.GetOrganizationName()
  time.sleep(1)
  print 'Maximum Users: ', adminObj.GetMaximumNumberOfUsers()
  time.sleep(1)
  print 'Current Users: ', adminObj.GetCurrentNumberOfUsers()
  time.sleep(1)
  print 'Domain is Verified: ',adminObj.IsDomainVerified()
  time.sleep(1)
  print 'Support PIN: ',adminObj.GetSupportPIN()
  time.sleep(1)
  print 'Domain Edition: ', adminObj.GetEdition()
  time.sleep(1)
  print 'Customer PIN: ', adminObj.GetCustomerPIN()
  time.sleep(1)
  print 'Domain Creation Time: ', adminObj.GetCreationTime()
  time.sleep(1)
  print 'Domain Country Code: ', adminObj.GetCountryCode()
  time.sleep(1)
  print 'Admin Secondary Email: ', adminObj.GetAdminSecondaryEmail()
  time.sleep(1)
  cnameverificationstatus = adminObj.GetCNAMEVerificationStatus()
  print 'CNAME Verification Record Name: ', cnameverificationstatus['recordName']
  print 'CNAME Verification Verified: ', cnameverificationstatus['verified']
  print 'CNAME Verification Method: ', cnameverificationstatus['verificationMethod']
  time.sleep(1)
  mxverificationstatus = adminObj.GetMXVerificationStatus()
  print 'MX Verification Verified: ', mxverificationstatus['verified']
  print 'MX Verification Method: ', mxverificationstatus['verificationMethod']
  time.sleep(1)
  ssosettings = adminObj.GetSSOSettings()
  print 'SSO Enabled: ', ssosettings['enableSSO']
  print 'SSO Signon Page: ', ssosettings['samlSignonUri']
  print 'SSO Logout Page: ', ssosettings['samlLogoutUri']
  print 'SSO Password Page: ', ssosettings['changePasswordUri']
  print 'SSO Whitelist IPs: ', ssosettings['ssoWhitelist']
  print 'SSO Use Domain Specific Issuer: ', ssosettings['useDomainSpecificIssuer']
  time.sleep(1)
  try:
    ssokey = adminObj.GetSSOKey()
  except gdata.apps.service.AppsForYourDomainException:
    ssokey = {}
  try:
    algorithm = str(ssokey['algorithm'])
    print 'SSO Key Algorithm: ' + algorithm
  except KeyError:
    pass
  try:
    format = str(ssokey['format'])
    print 'SSO Key Format: ' + format
  except KeyError:
    pass
  try:
    modulus = str(ssokey['modulus'])
    print 'SSO Key Modulus: ' + modulus
  except KeyError:
    pass
  try:
    exponent = str(ssokey['exponent'])
    print 'SSO Key Exponent: ' + exponent
  except KeyError:
    pass
  try:
    yValue = str(ssokey['yValue'])
    print 'SSO Key yValue: ' + yValue
  except KeyError:
    pass
  try:
    signingKey = str(ssokey['signingKey'])
    print 'Full SSO Key: ' + signingKey
  except KeyError:
    pass
  time.sleep(1)
  migration_status = adminObj.IsUserMigrationEnabled()
  print 'User Migration Enabled: ', str(migration_status)
  time.sleep(1)
  outbound_gateway_settings = adminObj.GetOutboundGatewaySettings()
  print 'Outbound Gateway Smart Host: ', outbound_gateway_settings['smartHost']
  try:
    print 'Outbound Gateway SMTP Mode: ', outbound_gateway_settings['smtpMode']
  except KeyError:
    print 'Not Set'

def doDeleteUser():
  user_name = sys.argv[3]
  apps = getAppsObject()
  if user_name.find('@') > 0:
    apps.domain = user_name[user_name.find('@')+1:]
    user_name = user_name[:user_name.find('@')]
  do_rename = True
  try:
    if sys.argv[4].lower() == 'norename':
      do_rename = False
  except IndexError:
    pass
  print "Deleting account for %s" % (user_name + '@' + apps.domain)
  #Rename the user to a random string, this allows the user to be recreated
  #immediately instead of waiting the usual 5 days
  user_to_delete = user_name
  if do_rename:
    timestamp = time.strftime("%Y%m%d%H%M%S")
    renameduser = user_name[:43]+'-'+timestamp+'-'    # include max 43 chars of username so there's room for datestamp and some randomness
    randomstring = ''.join(random.sample('abcdefghijklmnopqrstuvwxyz0123456789', 25))
    renameduser = renameduser+randomstring
    renameduser = renameduser[:64]
    user = apps.RetrieveUser(user_name)
    user.login.user_name = renameduser
    apps.UpdateUser(user_name, user)
    print 'Renamed account to: %s' % (renameduser + '@' + apps.domain)
    user_to_delete = renameduser
  apps.DeleteUser(user_to_delete)
  print 'Deleted user %s' % (user_to_delete + '@' + apps.domain)

def doDeleteGroup():
  group = sys.argv[3]
  groupObj = getGroupsObject()
  print "Deleting group %s" % group
  groupObj.DeleteGroup(group)

def doDeleteNickName():
  alias_email = sys.argv[3]
  multi = getMultiDomainObject()
  if alias_email.find('@') == -1:
    alias_email = '%s@%s' % (alias_email, domain)
  multi.DeleteAlias(alias_email=alias_email)

def doDeleteResourceCalendar():
  name = sys.argv[3]
  rescal = getResCalObject()
  rescal.DeleteResourceCalendar(name)

def doDeleteOrg():
  name = sys.argv[3]
  org = getOrgObject()
  try:
    org.DeleteOrganizationUnit(name)
  except gdata.apps.service.AppsForYourDomainException, e:
    if e.reason == 'EntityHasMembersCannotDelete':
      print 'Not Deleted. You must remove all users from an organization unit before deleting it.'
    elif e.reason == 'EntityDoesNotExist':
      print 'That Organization Unit does not exist.'
    else:
      print e.reason

def doPrintPostini():
  if os.path.isfile(getGamPath()+'postini-format.txt'):
    postini_format_file = open(getGamPath()+'postini-format.txt', 'rb')
    user_template = postini_format_file.readline()[0:-1]
    alias_template = postini_format_file.readline()[0:-1]
    group_template = postini_format_file.readline()
  else:
    user_template = 'adduser %user%'
    alias_template = 'addalias %user%, %alias%'
    group_template = 'addalias %list_owner%, %group%'
  try:
    list_owner = sys.argv[3]
  except IndexError:
    print 'You must include an email address that will own all group addresses'
    sys.exit(3)
  org = getOrgObject()
  sys.stderr.write("Getting all users in the %s organization (may take some time on a large Google Apps account)..." % org.domain)
  users = org.RetrieveAllOrganizationUsers()
  sys.stderr.write("done.\r\n")
  multi = getMultiDomainObject()
  sys.stderr.write("Getting all email aliases in the organization...")
  aliases = multi.RetrieveAllAliases()
  sys.stderr.write("done.\r\n")
  groupsObj = getGroupsObject()
  sys.stderr.write("Getting all groups in the organization...")
  groups = groupsObj.RetrieveAllGroups()
  sys.stderr.write("done.\r\n")
  print "# Begin Users"
  print ""
  for user in users:
    if user['orgUserEmail'][:2] == '.@' or user['orgUserEmail'][:11] == 'gcc_websvc@' or member['orgUserEmail'][-16:] == '@gtempaccount.com':  # not real users, skip em
        continue
    if user['orgUnitPath'] is None:
      user['orgUnitPath'] == ''
    print user_template.replace('%user%', str(user['orgUserEmail'])).replace('%ou%', str(user['orgUnitPath']))
  print ""
  print "# Begin Aliases"
  print ""
  for alias in aliases:
    print alias_template.replace('%user%', str(alias['userEmail'])).replace('%alias%', str(alias['aliasEmail']))
  print ""
  print "# Begin Groups"
  print ""
  for group in groups:
    print group_template.replace('%group%', str(group['groupId'])).replace('%name%', str(group['groupName'])).replace('%description%', str(group['description'])).replace('%list_owner%', list_owner)

def doPrintUsers():
  org = getOrgObject()
  sys.stderr.write("Getting all users in the %s organization (may take some time on a large Google Apps account)...\r\n" % org.domain)
  i = 3
  getUserFeed = getNickFeed = getGroupFeed = False
  firstname = lastname = username = ou = suspended = changepassword = agreed2terms = admin = nicknames = groups = False
  user_attributes = []
  # the titles list ensures the CSV output has its parameters in the specified order. 
  # Python's dicts can be listed in any order, and the order often changes between the
  # header (user_attributes[0]) and the actual data rows.
  titles = ['Email']
  user_attributes.append({'Email': 'Email'})
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'firstname':
      getUserFeed = True
      firstname = True
      user_attributes[0].update(Firstname='Firstname')
      titles.append('Firstname')
      i = i + 1
    elif sys.argv[i].lower() == 'lastname':
      getUserFeed = True
      lastname = True
      user_attributes[0].update(Lastname='Lastname')
      titles.append('Lastname')
      i = i + 1
    elif sys.argv[i].lower() == 'username':
      username = True
      user_attributes[0].update(Username='Username')
      titles.append('Username')
      i = i + 1
    elif sys.argv[i].lower() == 'ou':
      ou = True
      user_attributes[0].update(OU='OU')
      titles.append('OU')
      i = i + 1
    elif sys.argv[i].lower() == 'suspended':
      getUserFeed = True
      suspended = True
      user_attributes[0].update(Suspended='Suspended')
      titles.append('Suspended')
      i = i + 1
    elif sys.argv[i].lower() == 'changepassword':
      getUserFeed = True
      changepassword = True
      user_attributes[0].update(ChangePassword='ChangePassword')
      titles.append('ChangePassword')
      i = i + 1
    elif sys.argv[i].lower() == 'agreed2terms':
      getUserFeed = True
      agreed2terms = True
      user_attributes[0].update(AgreedToTerms='AgreedToTerms')
      titles.append('AgreedToTerms')
      i = i + 1
    elif sys.argv[i].lower() == 'admin':
      getUserFeed = True
      admin = True
      user_attributes[0].update(Admin='Admin')
      titles.append('Admin')
      i = i + 1
    elif sys.argv[i].lower() == 'nicknames' or sys.argv[i].lower() == 'aliases':
      getNickFeed = True
      nicknames = True
      user_attributes[0].update(Aliases='Aliases')
      titles.append('Aliases')
      i = i + 1
    elif sys.argv[i].lower() == 'groups':
      getGroupFeed = True
      groups = True
      user_attributes[0].update(Groups='Groups')
      titles.append('Groups')
      i = i + 1
    else:
      showUsage()
      exit(5)
  while True:
    try:
      all_users = org.RetrieveAllOrganizationUsers()
      sys.stderr.write("done.\r\n")
      break
    except gdata.apps.service.AppsForYourDomainException, e:
      print e
      continue
  domains = []
  for user in all_users:
    email = user['orgUserEmail'].lower()
    domain = email[email.find('@')+1:]
    if email[:2] == '.@' or email[:11] == 'gcc_websvc@' or email[:27] == 'secure-data-connector-user@' or email[-16:] == '@gtempaccount.com':  # not real users, skip em
      continue
    user_attributes.append({'Email': email})
    location = 0
    try:
      location = user_attributes.index({'Email': email})
      if username:
          user_attributes[location].update(Username=email[:email.find('@')])
      if ou:
          user_ou = user['orgUnitPath']
          if user_ou == None:
            user_ou = ''
          user_attributes[location].update(OU=user_ou)
    except ValueError:
      raise
    try:
      domains.index(domain)
    except ValueError:
      domains.append(domain)
    del(email, domain)
  apps = getAppsObject()
  if getUserFeed:
    for domain in domains:
      sys.stderr.write("Getting detailed info for users in %s domain (may take some time on a large domain)...\r\n" % domain)
      apps.domain = domain
      for page in apps.GetGeneratorForAllUsers():
        for user in page.entry:
          email = user.login.user_name.lower() + '@' + domain.lower()
          try:
            location = 0
            gotLocation = False
            while not gotLocation and location < len(user_attributes):
              location = location + 1
              try:
                if user_attributes[location]['Email'] == email:
                  gotLocation = True
              except IndexError:
                continue
            if firstname:
              userfirstname = user.name.given_name
              if userfirstname == None:
                userfirstname = ''
              try:
                user_attributes[location].update(Firstname=userfirstname)
              except IndexError:
                continue
            if lastname:
              userlastname = user.name.family_name
              if userlastname == None:
                userlastname = ''
              try:
                user_attributes[location].update(Lastname=userlastname)
              except IndexError:
                continue
            if suspended:
              try:
                user_attributes[location].update(Suspended=user.login.suspended)
              except IndexError:
                continue
            if agreed2terms:
              try:
                user_attributes[location].update(AgreedToTerms=user.login.agreed_to_terms)
              except IndexError:
                continue
            if changepassword:
              try:
                user_attributes[location].update(ChangePassword=user.login.change_password)
              except IndexError:
                continue
            if admin:
              try:
                user_attributes[location].update(Admin=user.login.admin)
              except IndexError:
                continue
          except ValueError:
            pass
          del (email)
  total_users = len(user_attributes)
  if getNickFeed:
    multi = getMultiDomainObject()
    user_count = 1
    for user in user_attributes:
      if user['Email'] == 'Email':
        continue
      nicknames = []
      while True:
        try:
          sys.stderr.write("Getting Aliases for %s (%s/%s)\r\n" % (user['Email'], user_count, total_users))
          nicknames = multi.GetUserAliases(user['Email'])
          break
        except gdata.apps.service.AppsForYourDomainException, e:
          if e.reason == 'EntityDoesNotExist':
            break
          continue
      nicklist = ''
      for nickname in nicknames:
        nicklist += nickname['aliasEmail']+' '
      user.update(Aliases=nicklist)
      user_count = user_count + 1
      del (nicknames, nicklist)
  if getGroupFeed:
    groupsObj = getGroupsObject()
    user_count = 1
    for user in user_attributes:
      if user['Email'] == 'Email':
        continue
      sys.stderr.write("Getting Group Membership for %s (%s/%s)\r\n" % (user['Email'], user_count, total_users))
      groupsObj.domain = user['Email'][user['Email'].find('@')+1:]
      username = user['Email'][:user['Email'].find('@')]
      groups = []
      while True:
        try:
          groups = groupsObj.RetrieveGroups(username)
          break
        except gdata.apps.service.AppsForYourDomainException, e:
          if e.reason == 'EntityDoesNotExist':
            break
          continue
      grouplist = ''
      for groupname in groups:
        grouplist += groupname['groupId']+' '
      user.update(Groups=grouplist)
      user_count = user_count + 1
      del (username, groups, grouplist)

  if os.name == 'windows':
    csv.register_dialect('winstdout', lineterminator='\r') # Stupid Windows always adds \n here...
    writer = csv.DictWriter(sys.stdout, fieldnames=titles, dialect='winstdout', quoting=csv.QUOTE_MINIMAL)
  else:
    csv.register_dialect('nixstdout', lineterminator='\n')
    writer = csv.DictWriter(sys.stdout, fieldnames=titles, dialect='nixstdout', quoting=csv.QUOTE_MINIMAL)
  writer.writerows(user_attributes)      

def doPrintGroups():
  i = 3
  printname = printdesc = printperm = usedomain = nousermanagedgroups = onlyusermanagedgroups = False
  group_attributes = []
  group_attributes.append({'GroupID': 'GroupID'})
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'name':
      printname = True
      group_attributes[0].update(Name='Name')
      i = i + 1
    elif sys.argv[i].lower() == 'description':
      group_attributes[0].update(Description='Description')
      printdesc = True
      i = i + 1
    elif sys.argv[i].lower() == 'permission':
      group_attributes[0].update(Permission='Permission')
      printperm = True
      i = i + 1
    elif sys.argv[i].lower() == 'domain':
      usedomain = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'nousermanagedgroups':
	  nousermanagedgroups = True
	  i = i + 1
    elif sys.argv[i].lower() == 'onlyusermanagedgroups':
      onlyusermanagedgroups = True
      i = i + 1
    else:
      showUsage()
      exit(7)
  groupsObj = getGroupsObject()
  if usedomain:
    groupsObj.domain = usedomain
  sys.stderr.write("Retrieving All Groups for domain %s (may take some time on large domain)..." % groupsObj.domain)
  if not onlyusermanagedgroups:
    all_groups = groupsObj.RetrieveAllGroups(nousermanagedgroups)
  else:
    admin_and_user_groups = groupsObj.RetrieveAllGroups(False)
    admin_groups = groupsObj.RetrieveAllGroups(True)
    all_groups = []
    for this_group in admin_and_user_groups:
      this_group_is_admin_created = False
      for that_group in admin_groups:
        if this_group['groupId'] == that_group['groupId']:
          this_group_is_admin_created = True
          break
      if not this_group_is_admin_created:
        all_groups.append(this_group)
  for group_vals in all_groups:
    group = {}
    group.update({'GroupID': group_vals['groupId']})
    if printname:
      name = group_vals['groupName']
      if name == None:
        name = ''
      group.update({'Name': name})
    if printdesc:
      description = group_vals['description']
      if description == None:
        description = ''
      group.update({'Description': description})
    if printperm:
      try:
        group.update({'Permission': group_vals['emailPermission']})
      except KeyError:
        group.update({'Permission': 'Unknown'})
    group_attributes.append(group)
  for row in group_attributes:
    for cell in row.values():
      print str(cell)+',',
    print ''

def doPrintNicknames():
  i = 3
  usedomain = False
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'domain':
      usedomain = sys.argv[i+1]
      i = i + 2
  multi = getMultiDomainObject()
  if usedomain:
    multi.domain = usedomain
  sys.stderr.write("Retrieving All Aliases for domain %s (may take some time on large domain)...\r\n\r\n" % multi.domain)
  print "Alias, User"
  nicknames = multi.RetrieveAllAliases()
  for nickname in nicknames:
    print "%s, %s" % (nickname['aliasEmail'], nickname['userEmail'])

def doPrintOrgs():
  i = 3
  printname = printdesc = printparent = printinherit = False
  org_attributes = []
  org_attributes.append({'Path': 'Path'})
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'name':
      printname = True
      org_attributes[0].update(Name='Name')
      i = i + 1
    elif sys.argv[i].lower() == 'description':
      printdesc = True
      org_attributes[0].update(Description='Description')
      i = i + 1
    elif sys.argv[i].lower() == 'parent':
      printparent = True
      org_attributes[0].update(Parent='Parent')
      i = i + 1
    elif sys.argv[i].lower() == 'inherit':
      printinherit = True
      org_attributes[0].update(InheritanceBlocked='InheritanceBlocked')
      i = i + 1
    else:
      showUsage()
      exit(8)
  org = getOrgObject()
  sys.stderr.write("Retrieving All Organizational Units for your account (may take some time on large domain)...")
  orgs = org.RetrieveAllOrganizationUnits()
  for org_vals in orgs:
    orgUnit = {}
    orgUnit.update({'Path': org_vals['orgUnitPath']})
    if printname:
      name = org_vals['name']
      if name == None:
        name = ''
      orgUnit.update({'Name': name})
    if printdesc:
      desc = org_vals['description']
      if desc == None:
        desc = ''
      orgUnit.update({'Description': desc})
    if printparent:
      parent = org_vals['parentOrgUnitPath']
      if parent == None:
        parent = ''
      orgUnit.update({'Parent': parent})
    if printinherit:
      orgUnit.update({'InheritanceBlocked': org_vals['blockInheritance']})
    org_attributes.append(orgUnit)
  for row in org_attributes:
    for cell in row.values():
      print str(cell)+',',
    print ''    

def doPrintResources():
  i = 3
  res_attributes = []
  res_attributes.append({'Name': 'Name'})
  titles = ['Name']
  printid = printdesc = printemail = False
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'id':
      printid = True
      res_attributes[0].update(ID='ID')
      titles.append('ID')
      i = i + 1
    elif sys.argv[i].lower() == 'description':
      printdesc = True
      res_attributes[0].update(Description='Description')
      titles.append('Description')
      i = i + 1
    elif sys.argv[i].lower() == 'email':
      printemail = True
      res_attributes[0].update(Email='Email')
      titles.append('Email')
      i = i + 1
    else:
      showUsage()
      sys.exit(2)
  resObj = getResCalObject()
  sys.stderr.write("Retrieving All Resource Calendars for your account (may take some time on a large domain)")
  resources = resObj.RetrieveAllResourceCalendars()
  for resource in resources:
    resUnit = {}
    resUnit.update({'Name': resource['resourceCommonName']})
    if printid:
      resUnit.update({'ID': resource['resourceId']})
    if printdesc:
      try:
        desc = resource['resourceDescription']
      except KeyError:
        desc = ''
      resUnit.update({'Description': desc})
    if printemail:
      resUnit.update({'Email': resource['resourceEmail']})
    res_attributes.append(resUnit)
  if os.name == 'windows':
    csv.register_dialect('winstdout', lineterminator='\r') # Stupid Windows always adds \n here...
    writer = csv.DictWriter(sys.stdout, fieldnames=titles, dialect='winstdout', quoting=csv.QUOTE_MINIMAL)
  else:
    csv.register_dialect('nixstdout', lineterminator='\n')
    writer = csv.DictWriter(sys.stdout, fieldnames=titles, dialect='nixstdout', quoting=csv.QUOTE_MINIMAL)
  writer.writerows(res_attributes)      


def hasAgreed2TOS(user_name):
  apps = getAppsObject()
  if user_name.find('@') > 0:
    apps.domain = user_name[user_name.find('@')+1:]
    user_name = user_name[:user_name.find('@')]
  userInfo = apps.RetrieveUser(user_name)
  if userInfo.login.agreed_to_terms == 'true':
    return True
  elif userInfo.login.agreed_to_terms == 'false':
    return False

def doCreateMonitor():
  source_user = sys.argv[4].lower()
  destination_user = sys.argv[5].lower()
  #end_date defaults to 30 days in the future...
  end_date = (datetime.datetime.now() + datetime.timedelta(days=30)).strftime("%Y-%m-%d %H:%M")
  begin_date = None
  incoming_headers_only = outgoing_headers_only = drafts_headers_only = chats_headers_only = False
  drafts = chats = True
  i = 6
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'end':
      end_date = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'begin':
      begin_date = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'incoming_headers':
      incoming_headers_only = True
      i = i + 1
    elif sys.argv[i].lower() == 'outgoing_headers':
      outgoing_headers_only = True
      i = i + 1
    elif sys.argv[i].lower() == 'nochats':
      chats = False
      i = i + 1
    elif sys.argv[i].lower() == 'nodrafts':
      drafts = False
      i = i + 1
    elif sys.argv[i].lower() == 'chat_headers':
      chats_headers_only = True
      i = i + 1
    elif sys.argv[i].lower() == 'draft_headers':
      drafts_headers_only = True
      i = i + 1
    else:
      showUsage()
      sys.exit(2)
  audit = getAuditObject()
  if source_user.find('@') > 0:
    audit.domain = source_user[source_user.find('@')+1:]
    source_user = source_user[:source_user.find('@')]

  results = audit.createEmailMonitor(source_user=source_user, destination_user=destination_user, end_date=end_date, begin_date=begin_date,
                           incoming_headers_only=incoming_headers_only, outgoing_headers_only=outgoing_headers_only,
                           drafts=drafts, drafts_headers_only=drafts_headers_only, chats=chats, chats_headers_only=chats_headers_only)

def doShowMonitors():
   user = sys.argv[4].lower()
   audit = getAuditObject()
   if user.find('@') > 0:
     audit.domain = user[user.find('@')+1:]
     user = user[:user.find('@')]
   results = audit.getEmailMonitors(user)
   print sys.argv[4].lower()+' has the following monitors:'
   print ''
   for monitor in results:
     print ' Destination: '+monitor['destUserName']
     try:
       print '  Begin: '+monitor['beginDate']
     except KeyError:
       print '  Begin: immediately'
     print '  End: '+monitor['endDate']
     print '  Monitor Incoming: '+monitor['outgoingEmailMonitorLevel']
     print '  Monitor Outgoing: '+monitor['incomingEmailMonitorLevel']
     print '  Monitor Chats: '+monitor['chatMonitorLevel']
     print '  Monitor Drafts: '+monitor['draftMonitorLevel']
     print ''

def doDeleteMonitor():
  source_user = sys.argv[4].lower()
  destination_user = sys.argv[5].lower()
  audit = getAuditObject()
  if source_user.find('@') > 0:
    audit.domain = source_user[source_user.find('@')+1:]
    source_user = source_user[:source_user.find('@')]
  results = audit.deleteEmailMonitor(source_user=source_user, destination_user=destination_user)

def doRequestActivity():
  user = sys.argv[4].lower()
  audit = getAuditObject()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  results = audit.createAccountInformationRequest(user)
  print 'Request successfully submitted:'
  print ' Request ID: '+results['requestId']
  print ' User: '+results['userEmailAddress']
  print ' Status: '+results['status']
  print ' Request Date: '+results['requestDate']
  print ' Requested By: '+results['adminEmailAddress']

def doStatusActivityRequests():
  audit = getAuditObject()
  try:
    user = sys.argv[4].lower()
    if user.find('@') > 0:
      audit.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    request_id = sys.argv[5].lower()
    results = audit.getAccountInformationRequestStatus(user, request_id)
    print ''
    print '  Request ID: '+results['requestId']
    print '  User: '+results['userEmailAddress']
    print '  Status: '+results['status']
    print '  Request Date: '+results['requestDate']
    print '  Requested By: '+results['adminEmailAddress']
    try:
      print '  Number Of Files: '+results['numberOfFiles']
      for i in range(int(results['numberOfFiles'])):
        print '  Url%s: %s' % (i, results['fileUrl%s' % i])
    except KeyError:
      pass
    print ''
  except IndexError:
    results = audit.getAllAccountInformationRequestsStatus()
    print 'Current Activity Requests:'
    print ''
    for request in results:
      print ' Request ID: '+request['requestId']
      print '  User: '+request['userEmailAddress']
      print '  Status: '+request['status']
      print '  Request Date: '+request['requestDate']
      print '  Requested By: '+request['adminEmailAddress']
      print ''

def doDownloadActivityRequest():
  user = sys.argv[4].lower()
  request_id = sys.argv[5].lower()
  audit = getAuditObject()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  results = audit.getAccountInformationRequestStatus(user, request_id)
  if results['status'] != 'COMPLETED':
    print 'Request needs to be completed before downloading, current status is: '+results['status']
    sys.exit(4)
  try:
    if int(results['numberOfFiles']) < 1:
      print 'ERROR: Request completed but no results were returned, try requesting again'
      sys.exit(4)
  except KeyError:
    print 'ERROR: Request completed but no files were returned, try requesting again'
    sys.exit(4)
  for i in range(0, int(results['numberOfFiles'])):
    url = results['fileUrl'+str(i)]
    filename = 'activity-'+user+'-'+request_id+'-'+str(i)+'.txt.gpg'
    print 'Downloading '+filename+' ('+str(i+1)+' of '+results['numberOfFiles']+')'
    geturl(url, filename)

def doRequestExport():
  begin_date = end_date = search_query = None
  headers_only = include_deleted = False
  user = sys.argv[4].lower()
  i = 5
  while i < len(sys.argv):
    if sys.argv[i].lower() == 'begin':
      begin_date = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'end':
      end_date = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'search':
      search_query = sys.argv[i+1]
      i = i + 2
    elif sys.argv[i].lower() == 'headersonly':
      headers_only = True
      i = i + 1
    elif sys.argv[i].lower() == 'includedeleted':
      include_deleted = True
      i = i + 1
    else:
      showUsage()
      sys.exit(2)
  audit = getAuditObject()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  results = audit.createMailboxExportRequest(user=user, begin_date=begin_date, end_date=end_date, include_deleted=include_deleted,
                                             search_query=search_query, headers_only=headers_only)
  print 'Export request successfully submitted:'
  print ' Request ID: '+results['requestId']
  print ' User: '+results['userEmailAddress']
  print ' Status: '+results['status']
  print ' Request Date: '+results['requestDate']
  print ' Requested By: '+results['adminEmailAddress']
  print ' Include Deleted: '+results['includeDeleted']
  print ' Requested Parts: '+results['packageContent']
  try:
    print ' Begin: '+results['beginDate']
  except KeyError:
    print ' Begin: account creation date'
  try:
    print ' End: '+results['endDate']
  except KeyError:
    print ' End: export request date'

def doDeleteExport():
  audit = getAuditObject()
  user = sys.argv[4].lower()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  request_id = sys.argv[5].lower()
  results = audit.deleteMailboxExportRequest(user=user, request_id=request_id)

def doDeleteActivityRequest():
  audit = getAuditObject()
  user = sys.argv[4].lower()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  request_id = sys.argv[5].lower()
  results = audit.deleteAccountInformationRequest(user=user, request_id=request_id)

def doStatusExportRequests():
  audit = getAuditObject()
  try:
    user = sys.argv[4].lower()
    if user.find('@') > 0:
      audit.domain = user[user.find('@')+1:]
      user = user[:user.find('@')]
    request_id = sys.argv[5].lower()
    results = audit.getMailboxExportRequestStatus(user, request_id)
    print ''
    print '  Request ID: '+results['requestId']
    print '  User: '+results['userEmailAddress']
    print '  Status: '+results['status']
    print '  Request Date: '+results['requestDate']
    print '  Requested By: '+results['adminEmailAddress']
    print '  Requested Parts: '+results['packageContent']
    try:
      print '  Request Filter: '+results['searchQuery']
    except KeyError:
      print '  Request Filter: None'
    print '  Include Deleted: '+results['includeDeleted']
    try:
      print '  Number Of Files: '+results['numberOfFiles']
      for i in range(int(results['numberOfFiles'])):
        print '  Url%s: %s' % (i, results['fileUrl%s' % i])
    except KeyError:
      pass
  except IndexError:
    results = audit.getAllMailboxExportRequestsStatus()
    print 'Current Export Requests:'
    print ''
    for request in results:
      print ' Request ID: '+request['requestId']
      print '  User: '+request['userEmailAddress']
      print '  Status: '+request['status']
      print '  Request Date: '+request['requestDate']
      print '  Requested By: '+request['adminEmailAddress']
      print '  Requested Parts: '+request['packageContent']
      try:
        print '  Request Filter: '+request['searchQuery']
      except KeyError:
        print '  Request Filter: None'
      print '  Include Deleted: '+request['includeDeleted']
      try:
        print '  Number Of Files: '+request['numberOfFiles']
      except KeyError:
        pass
      print ''
    
def doDownloadExportRequest():
  user = sys.argv[4].lower()
  request_id = sys.argv[5].lower()
  audit = getAuditObject()
  if user.find('@') > 0:
    audit.domain = user[user.find('@')+1:]
    user = user[:user.find('@')]
  results = audit.getMailboxExportRequestStatus(user, request_id)
  if results['status'] != 'COMPLETED':
    print 'Request needs to be completed before downloading, current status is: '+results['status']
    sys.exit(4)
  try:
    if int(results['numberOfFiles']) < 1:
      print 'ERROR: Request completed but no results were returned, try requesting again'
      sys.exit(4)
  except KeyError:
    print 'ERROR: Request completed but no files were returned, try requesting again'
    sys.exit(4)
  for i in range(0, int(results['numberOfFiles'])):
    url = results['fileUrl'+str(i)]
    filename = 'export-'+user+'-'+request_id+'-'+str(i)+'.mbox.gpg'
    #don't download existing files. This does not check validity of existing local
    #file so partial/corrupt downloads will need to be deleted manually.
    if os.path.isfile(filename):
      continue
    print 'Downloading '+filename+' ('+str(i+1)+' of '+results['numberOfFiles']+')'
    geturl(url, filename)

def doUploadAuditKey():
  auditkey = sys.stdin.read()
  audit = getAuditObject()
  results = audit.updatePGPKey(auditkey)

def doMoveUser():
  old_email = sys.argv[3].lower()
  new_email = sys.argv[4].lower()
  multi = getMultiDomainObject()
  multi.RenameUser(old_email=old_email, new_email=new_email)

def doCreateAlias():
  alias_email = sys.argv[4].lower()
  user_email = sys.argv[5].lower()
  multi = getMultiDomainObject()
  print 'Creating alias %s for user %s' % (alias_email, user_email)
  multi.CreateAlias(user_email=user_email, alias_email=alias_email)
  
def doInfoAlias():
  alias_email = sys.argv[4].lower()
  multi = getMultiDomainObject()
  results = multi.RetrieveAlias(alias_email=alias_email)
  print ''
  print ' Alias: '+results['aliasEmail']
  print ' User: '+results['userEmail']

def doDeleteAlias():
  alias_email = sys.argv[4].lower()
  multi = getMultiDomainObject()
  results = multi.DeleteAlias(alias_email=alias_email)

def getUsersToModify():
  entity = sys.argv[1].lower()
  if entity == 'user':
    users = [sys.argv[2].lower(),]
  elif entity == 'group':
    groupsObj = getGroupsObject()
    group = sys.argv[2].lower()
    print "Getting all members of %s (may take some time for large groups)..." % group
    members = groupsObj.RetrieveAllMembers(group)
    print "done.\r\n"
    users = []
    for member in members:
      users.append(member['memberId'][0:member['memberId'].find('@')])
  elif entity == 'ou':
    orgObj = getOrgObject()
    ou = sys.argv[2]
    print "Getting all users of %s Organizational Unit (May take some time for large OUs)..." % ou
    members = orgObj.RetrieveAllOrganizationUnitUsers(ou)
    print "done.\r\n"
    users = []
    for member in members:
      users.append(member['orgUserEmail'])
  elif entity == 'all':
    orgObj = getOrgObject()
    users = []
    print "Getting all users in the Google Apps %s organization (may take some time on a large domain)..." % orgObj.domain
    members = orgObj.RetrieveAllOrganizationUsers()
    for member in members:
      if member['orgUserEmail'][:2] == '.@' or member['orgUserEmail'][:11] == 'gcc_websvc@' or member['orgUserEmail'][:27] == 'secure-data-connector-user@' or member['orgUserEmail'][-16:] == '@gtempaccount.com':  # not real users, skip em
        continue
      users.append(member['orgUserEmail'])
    print "done.\r\n"
  else:
    showUsage()
    sys.exit(2)
  return users

def doRequestOAuth():
  domain = raw_input("\nEnter your Primary Google Apps Domain (e.g. example.com): ")
  print "\nIf you plan to use Group Settings commands, you\'ll need an Client ID and secret from the Google API console, see http://code.google.com/p/google-apps-manager/wiki/GettingAnOAuthConsoleKey for details. If you don\'t plan to use Group Settings commands you can just press enter here."
  client_key = raw_input("\nEnter your Client ID (e.g. XXXXXX.apps.googleusercontent.com or leave blank): ")
  if client_key == '':
    client_key = 'anonymous'
    client_secret = 'anonymous'
  else:
    client_secret = raw_input("\nEnter your Client secret: ")
  fetch_params = {'xoauth_displayname':'Google Apps Manager'}
  selected_scopes = ['*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*', '*']
  menu = '''Select the authorized scopes for this OAuth token and set the token name:

[%s] 0)  Group Provisioning
[%s] 1)  Email Alias Provisioning
[%s] 2)  Organizational Unit Provisioning
[%s] 3)  User Provisioning
[%s] 4)  User Email Settings
[%s] 5)  Calendar Resources
[%s] 6)  Audit Monitors, Activity and Mailbox Exports
[%s] 7)  Admin Settings
[%s] 8)  Admin Auditing
[%s] 9)  Group Settings API
[%s] 10) Profiles API (Hide / Unhide from contact sharing)
[%s] 11) Calendar Data API
[%s] 12) Reporting API

     13) Select all scopes
     14) Unselect all scopes
     15) Set OAuth token name (currently: %s)
     16) Continue
'''
  os.system(['clear','cls'][os.name == 'nt'])
  while True:
    selection = raw_input(menu % (selected_scopes[0], selected_scopes[1], selected_scopes[2], selected_scopes[3], selected_scopes[4], selected_scopes[5], selected_scopes[6], selected_scopes[7], selected_scopes[8], selected_scopes[9], selected_scopes[10], selected_scopes[11], selected_scopes[12], fetch_params['xoauth_displayname']))
    try:
      if int(selection) > -1 and int(selection) < 13:
        if selected_scopes[int(selection)] == ' ':
          selected_scopes[int(selection)] = '*'
        else:
          selected_scopes[int(selection)] = ' '
      elif selection == '13':
        for i in range(0, len(selected_scopes)):
          selected_scopes[i] = '*'
      elif selection == '14':
        for i in range(0, len(selected_scopes)):
           selected_scopes[i] = ' '
      elif selection == '15':
        fetch_params['xoauth_displayname'] = raw_input('Enter the name for your OAuth token: ')
      elif selection == '16':
        at_least_one = False
        for i in range(0, len(selected_scopes)):
          if selected_scopes[i] == '*':
            at_least_one = True
        if at_least_one:
          break
        else:
          os.system(['clear','cls'][os.name == 'nt'])
          print "You must select at least one scope!\n"
          continue
      else:
        os.system(['clear','cls'][os.name == 'nt'])
        print 'Not a valid selection.'
        continue
      os.system(['clear','cls'][os.name == 'nt'])
    except ValueError:
      os.system(['clear','cls'][os.name == 'nt'])
      print 'Not a valid selection.'
      continue

  possible_scopes = ['https://apps-apis.google.com/a/feeds/groups/',                      # Groups Provisioning API
                     'https://apps-apis.google.com/a/feeds/alias/',                       # Nickname Provisioning API
                     'https://apps-apis.google.com/a/feeds/policies/',                    # Organization Provisioning API
                     'https://apps-apis.google.com/a/feeds/user/',                        # Users Provisioning API
                     'https://apps-apis.google.com/a/feeds/emailsettings/2.0/',           # Email Settings API
                     'https://apps-apis.google.com/a/feeds/calendar/resource/',           # Calendar Resource API
                     'https://apps-apis.google.com/a/feeds/compliance/audit/',            # Audit API
                     'https://apps-apis.google.com/a/feeds/domain/',                      # Admin Settings API
                     'https://www.googleapis.com/auth/apps/reporting/audit.readonly',     # Admin Audit API
                     'https://www.googleapis.com/auth/apps.groups.settings',              # Group Settings API
                     'https://www.google.com/m8/feeds',                                   # Contacts / Profiles API
                     'https://www.google.com/calendar/feeds/',                            # Calendar Data API
                     'https://www.google.com/hosted/services/v1.0/reports/ReportingData'] # Reporting API
  scopes = []
  for i in range(0, len(selected_scopes)):
    if selected_scopes[i] == '*':
      scopes.append(possible_scopes[i])
  apps = gdata.apps.service.AppsService(domain=domain)
  apps = commonAppsObjInit(apps)
  apps.SetOAuthInputParameters(gdata.auth.OAuthSignatureMethod.HMAC_SHA1, consumer_key=client_key, consumer_secret=client_secret)
  try:
    request_token = apps.FetchOAuthRequestToken(scopes=scopes, extra_parameters=fetch_params)
  except gdata.service.FetchingOAuthRequestTokenFailed, e:
    if str(e).find('Timestamp') != -1:
      print "In order to use OAuth, your system time needs to be correct.\nPlease fix your time and try again."
      sys.exit(5)
    else:
      print "Error: %s" % e
      sys.exit(6)
  url_params = {'hd': domain}
  url = apps.GenerateOAuthAuthorizationURL(request_token=request_token, extra_params=url_params)
  raw_input("\nNow GAM will open a web page in order for you to grant %s access. Make sure you are logged in as an Administrator of your Google Apps domain before granting access. Press the Enter key to open your browser." % fetch_params['xoauth_displayname'])
  try:
    webbrowser.open(str(url))
  except Exception, e:
    pass
  raw_input("\n\nYou should now see a web page asking you to grant %s\n"
            'access. If the page didn\'t open, you can manually\n'
            'go to\n\n%s\n\nto grant access.\n'
            '\n'
            'Once you\'ve granted access, press the Enter key.' % (fetch_params['xoauth_displayname'], url))
  try:
    final_token = apps.UpgradeToOAuthAccessToken(request_token)
  except gdata.service.TokenUpgradeFailed:
    print 'Failed to upgrade the token. Did you grant GAM access in your browser?'
    exit(4)
  oauth_filename = 'oauth.txt'
  try:
    oauth_filename = os.environ['OAUTHFILE']
  except KeyError:
    pass
  f = open(getGamPath()+oauth_filename, 'wb')
  f.write('%s\n' % (domain,))
  pickle.dump(final_token, f)
  f.close()

try:
  if sys.argv[1].lower() == 'version':
    doGAMVersion()
    exit(0)
  if sys.argv[1].lower() == 'create':
    if sys.argv[2].lower() == 'user':
      doCreateUser()
    elif sys.argv[2].lower() == 'group':
      doCreateGroup()
    elif sys.argv[2].lower() == 'nickname' or sys.argv[2].lower() == 'alias':
      doCreateNickName()
    elif sys.argv[2].lower() == 'org':
      doCreateOrg()
    elif sys.argv[2].lower() == 'resource':
      doCreateResource()
    sys.exit(0)
  elif sys.argv[1].lower() == 'update':
    if sys.argv[2].lower() == 'user':
      doUpdateUser()
    elif sys.argv[2].lower() == 'group':
      doUpdateGroup()
    elif sys.argv[2].lower() == 'nickname' or sys.argv[2].lower() == 'alias':
      doUpdateNickName()
    elif sys.argv[2].lower() == 'org':
      doUpdateOrg()
    elif sys.argv[2].lower() == 'resource':
      doUpdateResourceCalendar()
    elif sys.argv[2].lower() == 'domain':
      doUpdateDomain()
    else:
      showUsage()
      print 'Error: invalid argument to "gam update..."'
      sys.exit(2)
    sys.exit(0)
  elif sys.argv[1].lower() == 'info':
    if sys.argv[2].lower() == 'user':
      doGetUserInfo()
    elif sys.argv[2].lower() == 'group':
      doGetGroupInfo()
    elif sys.argv[2].lower() == 'nickname' or sys.argv[2].lower() == 'alias':
      doGetNickNameInfo()
    elif sys.argv[2].lower() == 'domain':
      doGetDomainInfo()
    elif sys.argv[2].lower() == 'org':
      doGetOrgInfo()
    elif sys.argv[2].lower() == 'resource':
      doGetResourceCalendarInfo()
    sys.exit(0)
  elif sys.argv[1].lower() == 'delete':
    if sys.argv[2].lower() == 'user':
      doDeleteUser()
    elif sys.argv[2].lower() == 'group':
      doDeleteGroup()
    elif sys.argv[2].lower() == 'nickname' or sys.argv[2].lower() == 'alias':
      doDeleteNickName()
    elif sys.argv[2].lower() == 'org':
      doDeleteOrg()
    elif sys.argv[2].lower() == 'resource':
      doDeleteResourceCalendar()
    sys.exit(0)
  elif sys.argv[1].lower() == 'audit':
    if sys.argv[2].lower() == 'monitor':
      if sys.argv[3].lower() == 'create':
        doCreateMonitor()
      elif sys.argv[3].lower() == 'list':
        doShowMonitors()
      elif sys.argv[3].lower() == 'delete':
        doDeleteMonitor()
    elif sys.argv[2].lower() == 'activity':
      if sys.argv[3].lower() == 'request':
        doRequestActivity()
      elif sys.argv[3].lower() == 'status':
        doStatusActivityRequests()
      elif sys.argv[3].lower() == 'download':
        doDownloadActivityRequest()
      elif sys.argv[3].lower() == 'delete':
        doDeleteActivityRequest()
    elif sys.argv[2].lower() == 'export':
      if sys.argv[3].lower() == 'status':
        doStatusExportRequests()
      elif sys.argv[3].lower() == 'download':
        doDownloadExportRequest()
      elif sys.argv[3].lower() == 'request':
        doRequestExport()
      elif sys.argv[3].lower() == 'delete':
        doDeleteExport()
    elif sys.argv[2].lower() == 'uploadkey':
      doUploadAuditKey()
    elif sys.argv[2].lower() == 'admin':
      doAdminAudit()
    sys.exit(0)
  elif sys.argv[1].lower() == 'multi':
    if sys.argv[2].lower() == 'move':
      doMoveUser()
    elif sys.argv[2].lower() == 'alias':
      if sys.argv[3].lower() == 'create':
        doCreateAlias()
      elif sys.argv[3].lower() == 'info':
        doInfoAlias()
      elif sys.argv[3].lower() == 'delete':
        doDeleteAlias()
    sys.exit(0)
  elif sys.argv[1].lower() == 'print':
    if sys.argv[2].lower() == 'users':
      doPrintUsers()
    elif sys.argv[2].lower() == 'nicknames' or sys.argv[2].lower() == 'aliases':
      doPrintNicknames()
    elif sys.argv[2].lower() == 'groups':
      doPrintGroups()
    elif sys.argv[2].lower() == 'orgs':
      doPrintOrgs()
    elif sys.argv[2].lower() == 'resources':
      doPrintResources()
    elif sys.argv[2].lower() == 'postini':
      doPrintPostini()
    sys.exit(0)
  elif sys.argv[1].lower() == 'oauth':
    if sys.argv[2].lower() == 'request':
      doRequestOAuth()
    sys.exit(0)
  elif sys.argv[1].lower() == 'calendar':
    if sys.argv[3].lower() == 'showacl':
      doCalendarShowACL()
    elif sys.argv[3].lower() == 'add':
      doCalendarAddACL()
    elif sys.argv[3].lower() == 'del' or sys.argv[3].lower() == 'delete':
      doCalendarDelACL()
    elif sys.argv[3].lower() == 'update':
      doCalendarUpdateACL()
    sys.exit(0)
  elif sys.argv[1].lower() == 'report':
    showReport()
    sys.exit(0)
  users = getUsersToModify()
  command = sys.argv[3].lower()
  if command == 'print':
    for user in users:
      print user
  elif command == 'show':
    readWhat = sys.argv[4].lower()
    if readWhat == 'labels' or readWhat == 'label':
      showLabels(users)
    elif readWhat == 'profile':
      showProfile(users)
    elif readWhat == 'calendars':
      showCalendars(users)
    elif readWhat == 'calsettings':
      showCalSettings(users)
    elif readWhat == 'sendas':
      showSendAs(users)
    elif readWhat == 'sig' or readWhat == 'signature':
      getSignature(users)
    elif readWhat == 'forward':
      getForward(users)
    elif readWhat == 'pop' or readWhat == 'pop3':
      getPop(users)
    elif readWhat == 'imap' or readWhat == 'imap4':
      getImap(users)
    elif readWhat == 'vacation':
      getVacation(users)
    elif readWhat == 'delegate' or readWhat == 'delegates':
      getDelegates(users)
  elif command == 'delete' or command == 'del':
    delWhat = sys.argv[4].lower()
    if delWhat == 'delegate':
      deleteDelegate(users)
    elif delWhat == 'calendar':
      deleteCalendar(users)
    elif delWhat == 'label':
      doDeleteLabel(users)
    elif delWhat == 'photo':
      deletePhoto(users)
  elif command == 'add':
    addWhat = sys.argv[4].lower()
    if addWhat == 'calendar':
      addCalendar(users)
  elif command == 'update':
    if sys.argv[4].lower() == 'calendar':
	    updateCalendar(users)
    elif sys.argv[4].lower() == 'photo':
      doPhoto(users)
  elif command == 'get':
    if sys.argv[4].lower() == 'photo':
      getPhoto(users)
  elif command == 'profile':
    doProfile(users)
  elif command == 'imap':
    doImap(users)
  elif command == 'pop' or command == 'pop3':
    doPop(users)
  elif command == 'sendas':
    doSendAs(users)
  elif command == 'language':
    doLanguage(users)
  elif command == 'utf' or command == 'utf8' or command == 'utf-8' or command == 'unicode':
    doUTF(users)
  elif command == 'pagesize':
    doPageSize(users)
  elif command == 'shortcuts':
    doShortCuts(users)
  elif command == 'arrows':
    doArrows(users)
  elif command == 'snippets':
    doSnippets(users)
  elif command == 'label':
    doLabel(users)
  elif command == 'filter':
    doFilter(users)
  elif command == 'forward':
    doForward(users)
  elif command == 'sig' or command == 'signature':
    doSignature(users)
  elif command == 'vacation':
    doVacation(users)
  elif command == 'webclips':
    doWebClips(users)
  elif command == 'delegate' or command == 'delegates':
    doDelegates(users)
  else:
    showUsage()
    sys.exit(2)
except IndexError:
  showUsage()
  sys.exit(2)
except KeyboardInterrupt:
  sys.exit(50)