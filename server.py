#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer # the heavy lifting of the web server
import urllib # some url parsing support
import json # support for json encoding
import sys # needed for agument handling
import sqlite3
import time
import secrets
import datetime
from collections import defaultdict
from dateutil import relativedelta

def current_time():
    '''fetches the current timestamp'''
    now = int(time.time())
    return now

def to_date(epoch):
    '''converts timestamp to date'''
    today=datetime.datetime.fromtimestamp(epoch)
    today=today.strftime('%Y-%m-%d')
    return today

def access_database(database,query):
    '''used to execute insert,update and delete query'''
    connect = sqlite3.connect(database)
    cur = connect.cursor()
    if len(query)>1:
        cur.execute(query[0],query[1])
    else:
        cur.execute(query[0])
    connect.commit()
    connect.close()


def access_database_with_result(database, query):
    '''used to execute select query'''
    connect = sqlite3.connect(database)
    connect.create_function('traffic_today',1,to_date)
    connect.create_function('last_day',1,last_work_day)
    cur = connect.cursor()
    if len(query)>1:
        rows=cur.execute(query[0],query[1]).fetchall()
    else:
        rows=cur.execute(query[0]).fetchall()
    connect.commit()
    connect.close()
    return rows

def last_work_day():
    '''fetches last work day'''
    query=['select max(traffic_today(end)) from session where end!=?',[0]]
    rows=access_database_with_result('traffic.db',query)
    return rows

def userid():
    '''returns a dictionary of users with last work day and list of work hours'''
    query=['select userid from users']
    users=access_database_with_result('traffic.db',query)
    users={user[0]:['NULL',0,0,0,] for user in users}
    for user in users.keys():
        if len(last_work_day())>0:
            users[user][0]=last_work_day()[0][0]
    return users

def day(i_d,date_l):
    '''Calculates no of hours worked in a day'''
    hours=0.0
    query=['select round(sum((1.0*abs(end-start))/(60*60)),1) from session where userid=? and traffic_today(end)=? and end!=?',[i_d,date_l,0]]
    rows=access_database_with_result('traffic.db',query)
    if rows[0][0] is not None:
        hours=rows[0][0]
    return hours

def week(i_d,date_l):
    '''Calculates no of hours worked in a week'''
    hours=0.0
    days = datetime.timedelta(6)
    date=datetime.datetime.strptime(date_l,'%Y-%m-%d').date()
    s_date=date-days
    query=['select round(sum((1.0*abs(end-start))/(60*60)),1) from session where userid=? and traffic_today(end)>=? and traffic_today(end)<=? and end!=?',[i_d,s_date,date_l,0]]
    rows=access_database_with_result('traffic.db',query)
    if rows[0][0] is not None:
        hours=rows[0][0]
    return hours

def month(i_d,date_l):
    '''fetches the no of hours worked in a month'''
    hours=0.0
    days=relativedelta.relativedelta(months=1)
    date=datetime.datetime.strptime(date_l,'%Y-%m-%d').date()
    s_date=date-days
    query=['select round(sum((1.0*abs(end-start))/(60*60)),1) from session where userid=? and traffic_today(end)>? and traffic_today(end)<=? and end!=?',[i_d,s_date,date_l,0]]
    rows=access_database_with_result('traffic.db',query)
    if rows[0][0] is not None:
        hours=rows[0][0]
    return hours

def traffic_summary():
    '''Generates traffic summary for the most recent day(max(time)) in the traffic table with mode=1(active record) for traffic.csv'''
    vehicle= {0:"car",3:"taxi",7:"bus",5:"motorbike",6:"bicycle",1:"van", 2:"truck",4:"other"}
    query=['select traffic_today(max(time)) from traffic where mode=?',[1]]
    date_latest=access_database_with_result('traffic.db',query)
    query=['select traffic_today(time),location,type,occupancy,count(occupancy) from traffic where traffic_today(time)=? and mode=? group by location,type,occupancy order by location,type,occupancy',[date_latest[0][0],1]]
    rows=access_database_with_result('traffic.db',query)
    summary=defaultdict(dict)
    res=''
    for row in rows:
        summary[row[1]][vehicle[row[2]]]=[0,0,0,0]
    for row in rows:
        summary[row[1]][vehicle[row[2]]][row[3]-1]=row[4]
    for loc,typ in summary.items():
        for key,val in typ.items():
            if sum(val)!=0:
                res+='"{0}",{1},{2},{3},{4},{5}\n'.format(loc,key,val[0],val[1],val[2],val[3])
    return res


def build_response_refill(where, what):
    """This function builds a refill action that allows part of the
        currently loaded page to be replaced."""
    return {"type":"refill","where":where,"what":what}


def build_response_redirect(where):
    """This function builds the page redirection action
        It indicates which page the client should fetch.
        If this action is used, only one instance of it should
        contained in the response and there should be no refill action."""
    return {"type":"redirect", "where":where}


def handle_validate(iuser, imagic):
    """Decide if the combination of user and magic is valid"""
    ## alter as required
    query=["select * from session where userid=? and magic=? and end=? ",[iuser,imagic,0]]
    row=access_database_with_result('traffic.db',query)
    if len(row)!=0:
        return True
    return False

def handle_delete_session(iuser, imagic):
    """Remove the combination of user and magic from the data base, ending the login"""
    query=["update session set end=? where userid=? and magic=? and end=?",[current_time(),iuser,imagic,0]]
    access_database('traffic.db',query)
    return

def handle_login_request(iuser, imagic, parameters):
    """A user has supplied a username (parameters['usernameinput'][0])
    and password (parameters['passwordinput'][0]) check if these are
    valid and if so, create a suitable session record in the database
    with a random magic identifier that is returned.
    Return the username, magic identifier and the response action set."""
    response = []
    if (('usernameinput' in parameters) and ('passwordinput' in parameters)):
        #check the credentials
        query=["select userid from users where username=? and password=?",[parameters['usernameinput'][0],parameters['passwordinput'][0]]]
        row=access_database_with_result('traffic.db',query)
        if len(row)!=0:# if credentials match
            user=row[0][0]            #assign the userid to user variable
            query=["select * from session where userid=? and end=? ",[user,0]] #fetch the session id where userid and end match
            row=access_database_with_result('traffic.db',query)
            # check if the user is valid.Check for same browser login
            if handle_validate(iuser, imagic) is True:
            # the user is already logged in, so end the existing session.
                handle_delete_session(iuser, imagic)
            else: # check if the validate fails if there is any user with end=0 and userid
                query=['select * from session where userid=? and end=?',[user,0]]
                rows=access_database_with_result('traffic.db',query)
                if len(rows)!=0:
                    query=["update session set end=? where userid=? and end=?",[current_time(),user,0]]
                    access_database('traffic.db',query)
                ## alter as required
        #        # Generate magic token and insert into session
            magic=secrets.token_urlsafe(16)
            query=["insert into session(userid, magic, start, end) values(?,?,?,?)",[user,magic,current_time(),0]]
            access_database('traffic.db',query)
            response.append(build_response_redirect('/page.html'))
            return [user, magic, response]
        else: ## The user is not valid
            response.append(build_response_refill('message', 'Invalid credentials'))
            user = '!'
            magic = ''
            return [user, magic, response]
    else:    # empty fields
        response.append(build_response_refill('message', 'empty userid or password input'))
        user = '!'
        magic = ''
    return [user, magic, response]


def handle_add_request(iuser, imagic, parameters):
    """The user has requested a vehicle be added to the count
        parameters['locationinput'][0] the location to be recorded
        parameters['occupancyinput'][0] the occupant count to be recorded
        parameters['typeinput'][0] the type to be recorded
        Return the username, magic identifier (these can be empty  strings)
        and the response action set."""
    response = []
    ## alter as required
    vehicle= {"car": 0, "van":1, "truck":2,"taxi":3, "other":4, "motorbike":5, "bicycle":6, "bus":7}
    if handle_validate(iuser, imagic) is not True:
        #Invalid sessions redirect to login
        response.append(build_response_refill('message','invalid session'))
        response.append(build_response_refill('total', '0'))
        response.append(build_response_redirect('/index.html'))
        user='!'
        magic=''
    else:
        if (('locationinput' in parameters.keys()) and ('occupancyinput' in parameters.keys()) and ('typeinput' in parameters.keys())):
            if parameters['occupancyinput'][0] in ['1','2','3','4']:
                if parameters['typeinput'][0] in vehicle.keys():
                    query=["select sessionid from session where userid=? and magic=? and end=?",[iuser,imagic,0]]
                    sid=access_database_with_result('traffic.db',query)
                    query=["insert into traffic (sessionid,time,type,occupancy,location,mode) values (?,?,?,?,?,?)",[sid[0][0],current_time(),vehicle[parameters['typeinput'][0]],parameters['occupancyinput'][0],parameters['locationinput'][0],1]]
                    access_database('traffic.db',query)
                    response.append(build_response_refill('message', 'Entry added.'))
                    query=["select count(type) from traffic where sessionid=? and mode=?",[sid[0][0],1]]
                    total=access_database_with_result('traffic.db',query)
                    response.append(build_response_refill('total',str(total[0][0])))
                    user=iuser
                    magic=imagic
                else:
                    response.append(build_response_refill('message', 'Invalid type'))
                    response.append(build_response_refill('total', '0'))
                    user=iuser
                    magic=imagic
            else:
                response.append(build_response_refill('message', 'Invalid occupancy'))
                response.append(build_response_refill('total', '0'))
                user=iuser
                magic=imagic
        else:
            response.append(build_response_refill('message', 'missing location or occupancy or vehicle type'))
            response.append(build_response_refill('total', '0'))
            user=iuser
            magic=imagic
    return [user, magic,response]


def handle_undo_request(iuser, imagic, parameters):
    """The user has requested a vehicle be removed from the count
        This is intended to allow counters to correct errors.
        parameters['locationinput'][0] the location to be recorded
        parameters['occupancyinput'][0] the occupant count to be recorded
        parameters['typeinput'][0] the type to be recorded
        Return the username, magic identifier (these can be empty  strings) and
        the response action set."""
    vehicle= {"car": 0, "van":1, "truck":2,"taxi":3, "other":4, "motorbike":5, "bicycle":6, "bus":7}
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) is not True:
            #Invalid sessions redirect to login
        response.append(build_response_refill('message', 'Invalid session'))
        response.append(build_response_refill('total', str('0')))
        response.append(build_response_redirect('/index.html'))
        user='!'
        magic=''
    else:
        if (('locationinput' in parameters.keys()) and ('occupancyinput' in parameters.keys()) and ('typeinput' in parameters.keys())):
            if parameters['occupancyinput'][0] in ['1','2','3','4']:
                if  parameters['typeinput'][0] in vehicle.keys():
                # else: ## a valid session so process the recording of the entry.
                    query=["select sessionid from session where userid=? and magic=? and end=? ",[str(iuser),imagic,0]]
                    sid=access_database_with_result('traffic.db',query)
                    query=['select * from traffic where sessionid=? and type=? and occupancy=? and location=? and mode=?',[sid[0][0],vehicle[parameters['typeinput'][0]],parameters['occupancyinput'][0],parameters['locationinput'][0],1]]
                    row=access_database_with_result('traffic.db',query)
                    if len(row)!=0:
                        query=['select max(time) from traffic where sessionid=? and type=? and occupancy=? and location=? and mode=?',[sid[0][0],vehicle[parameters['typeinput'][0]],parameters['occupancyinput'][0],parameters['locationinput'][0],1]]
                        recent=access_database_with_result('traffic.db',query)
                        query=['update traffic set mode=? where sessionid=? and type=? and occupancy=? and location=? and mode=? and time=?',[2,sid[0][0],vehicle[parameters['typeinput'][0]],parameters['occupancyinput'][0],parameters['locationinput'][0],1,recent[0][0]]]
                        access_database('traffic.db',query)
                        query=['insert into traffic (sessionid,time,type,occupancy,location,mode) values(?,?,?,?,?,?)',[sid[0][0],current_time(),vehicle[parameters['typeinput'][0]],parameters['occupancyinput'][0],parameters['locationinput'][0],0]]
                        access_database('traffic.db',query)
                        response.append(build_response_refill('message', 'Entry Un-done.'))
                        
                    else:
                        response.append(build_response_refill('message', 'No matching record found.Cannot undo.'))
                    query=["select count(type) from traffic where sessionid=? and mode=?",[sid[0][0],1]]
                    total=access_database_with_result('traffic.db',query)
                    response.append(build_response_refill('total', str(total[0][0])))
                    user=iuser
                    magic=imagic
                else:
                    response.append(build_response_refill('message', 'Please provide valid type input'))
                    response.append(build_response_refill('total',str('0')))
                    user=iuser
                    magic=imagic

            else:
                response.append(build_response_refill('message', 'Please provide valid occupancy input'))
                response.append(build_response_refill('total',str('0')))
                user=iuser
                magic=imagic

        else:
            response.append(build_response_refill('message', 'missing location or occupancy or vehicle type'))
            response.append(build_response_refill('total',str('0')))
            user=iuser
            magic=imagic
    return [user, magic, response]


def handle_back_request(iuser, imagic, parameters):
    """This code handles the selection of the back button on the record form (page.html)
        You will only need to modify this code if 
        you make changes elsewhere that break its behaviour"""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) is not True:
        response.append(build_response_refill('message','invalid session'))
        response.append(build_response_refill('total', '0'))
        response.append(build_response_redirect('/index.html'))
        user = '!'
        magic = ''
    else:
        response.append(build_response_redirect('/summary.html'))
        query=["select sessionid from session where userid=? and magic=? and end=?",[iuser,imagic,0]]
        sid=access_database_with_result('traffic.db',query)
        query=["select count(type) from traffic where sessionid=? and mode=?",[sid[0][0],1]]
        total=access_database_with_result('traffic.db',query)
        response.append(build_response_refill('total',str(total[0][0])))
        response.append(build_response_refill('total', '0'))
        user = iuser
        magic = imagic   
    return [user, magic, response]


def handle_logout_request(iuser, imagic, parameters):
    """This code handles the selection of the logout button on the summary page (summary.html)
        You will need to ensure the end of the session is recorded in the database
        And that the session magic is revoked."""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) is True:
        handle_delete_session(iuser, imagic)
    response.append(build_response_redirect('/index.html'))
    user = '!'
    magic = ''
    return [user, magic, response]


def handle_summary_request(iuser, imagic,parameters):
    """This code handles a request for an update to the session summary values.
        You will need to extract this information from the database.
        You must return a value for all vehicle types, even when it's zero."""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) is not True:
        #Invalid sessions redirect to login
        response.append(build_response_refill('message', 'Invalid session'))
        response.append(build_response_refill('total', str('0')))
        response.append(build_response_redirect('/index.html'))
        user = '!'
        magic = ''
    else: ## a valid session so process the recording of the entry.
        vehicle= {0:["car",0],3:["taxi",0],7: ["bus",0],5:["motorbike",0],6:["bicycle",0],1:["van",0], 2:["truck",0],4:["other",0]}    
        query=['select sessionid from session where userid=? and magic=? and end=?',[iuser,imagic,0]]
        sid=access_database_with_result('traffic.db',query)
        query=['select type,count(type) from traffic where sessionid=? and mode=? GROUP BY type ORDER BY type',[sid[0][0],1]]
        statistics=access_database_with_result('traffic.db',query)
        for stat in statistics:
            vehicle[stat[0]][1]=stat[1]
        for veh in vehicle.values():
            response.append(build_response_refill('sum_{}'.format(veh[0]),veh[1]))
        query=["select count(type) from traffic where sessionid=? and mode=?",[sid[0][0],1]]
        total=access_database_with_result('traffic.db',query)
        response.append(build_response_refill('total', str(total[0][0])))
        user = iuser
        magic = imagic
    return [user, magic, response]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):
    '''
    # GET This function responds to GET requests to the web server.'''
    def do_GET(self):
        '''
        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.'''

        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            # print(rcookies.items())
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value                
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)
        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()            
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response=[]
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        elif parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], parameters)
                    #The result of a login attempt will be to 
                    # set the cookies to identify the session
                    set_cookies(self, user, magic)                    
                elif parameters['command'][0] == 'add':
                    [user, magic, response] = handle_add_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, response] = handle_undo_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, response] = handle_back_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    response = []
                    response.append(build_response_refill('message', 'Internal Error: Command not recognised.'))
            else:
                # There was no command present, report that to the user.
                response = []
                response.append(build_response_refill('message', 'Internal Error: Command not found.'))
            text = json.dumps(response)
            print(text)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))
        elif self.path.endswith('/statistics/hours.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for /statistics/hours.csv should be handled.
            ## you should check a valid user is logged in. You are encouraged to wrap this behavour in a function.
            response=[]
            # user_magic = get_cookies(self)
            if handle_validate(user_magic[0], user_magic[1]) is not True:
            #Invalid sessions redirect to login
                response.append(build_response_refill('message', 'Invalid session'))
                response.append(build_response_refill('total', str('0')))            
                response.append(build_response_redirect('/index.html'))
                user = '!'
                magic = ''
            else:
                users=userid()
                for user in users.keys():
                    if users[user][0] is not None:
                        users[user][1]=day(user,users[user][0])
                        users[user][2]=week(user,users[user][0])
                        users[user][3]=month(user,users[user][0])
                text = "Username,Day,Week,Month\n"
                for user in users.keys():
                    text+="test{0},{1},{2},{3}\n".format(user,users[user][1],users[user][2],users[user][3])
                encoded = bytes(text, 'utf-8')
                self.send_response(200)
                self.send_header('Content-type', 'text/csv')
                self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('hours.csv'))
                self.send_header("Content-Length", len(encoded))
                self.end_headers()
                self.wfile.write(encoded)

        elif self.path.endswith('/statistics/traffic.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for  /statistics/traffic.csv should be handled.
            ## you should check a valid user is checked in.
            #  You are encouraged to wrap this behavour in a function.
            response=[]
            if handle_validate(user_magic[0], user_magic[1]) is not  True:
            #Invalid sessions redirect to login
                response.append(build_response_refill('message', 'Invalid session'))
                response.append(build_response_refill('total', str('0')))
                response.append(build_response_redirect('/index.html'))
                user = '!'
                magic = ''
            else:
                text = "This should be the content of the csv file."
                text = "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"
                text+=traffic_summary()
                encoded = bytes(text, 'utf-8')
                self.send_response(200)
                self.send_header('Content-type', 'text/csv')
                self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('traffic.csv'))
                self.send_header("Content-Length", len(encoded))
                self.end_headers()
                self.wfile.write(encoded)

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

def run():
    """This is the entry point function to this code."""
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    if len(sys.argv)<2: # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server on port =',sys.argv[1],'...')
    httpd.serve_forever() # This function will not return till the server is aborted.
    # print("abc")
run()
