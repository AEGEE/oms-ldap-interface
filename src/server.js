const ldap = require('ldapjs');
const request = require('request');


var server = ldap.createServer();

const config = {
   basedn: 'o=example',
   server: {
    url: 'https://my.aegee.eu',
    login_route: '/services/oms-core-elixir/api/login',
    refresh_route: '/services/oms-core-elixir/api/renew',
    members_route: '/services/oms-core-elixir/api/members'
  }
}

var logged_in_users = {}

function authenticate(req, res, next) {
  username = req.connection.ldap.bindDN.toString()
  // If username doesn't exist, the user didn't BIND
  if(!(username in logged_in_users) || username == 'anonymous') {
    return next(new InsufficientAccessRightsError())
  }

  user = logged_in_users[username]
  req.user = user
  // Check how old the access token is
  // If more than 3 minutes, get a new access token
  if(Date.now() - user.t > 180000) {
    console.log("Requesting new access token")
    request({
      url: config.server.url + config.server.refresh_route,
      method: 'POST',
      json: true,
      body: {refresh_token: user.ref}
    }, (error, res, body) => {
      // Something went wrong in communicating to host
      if(error) {
        console.log("Could not contact myaegee server")
        console.log(error)
        return next(new UnavailableError())
      }

      // The refresh token timed out
      if(res.statusCode == 403) {
        return next(new InsufficientAccessRightsError())
      }

      if(!body.success) {
        return next(new OtherError())
      }

      logged_in_users[username].acc = body.access_token

      return next()
    })
  }
  else {
    return next()
  }
}

// Search for members
server.search('ou=people,ou=intranet,ou=Zeus,o=AEGEE,c=FR', [authenticate], function(req, res, next) {
  const request_more_members = function(offset, previous_results) {
    console.log("Forwarding items... " + offset);
    request({
      url: config.server.url + config.server.members_route,
      method: 'GET',
      json: true,
      headers: {"x-auth-token": req.user.acc},
      qs: {limit: 250, offset: offset}
    }, (error, foreign_res, body) => {
      // If we still got results, process them
      if(body.data && body.data.length) {
        // Push previous results
        previous_results.push(body.data);

        // Send those objects which match
        // First map results to ldap format
        // Then apply the filter
        // Lastly send them
        var members = body.data.map((x) => {
          return {
            dn: 'ou=people,ou=intranet,ou=Zeus,o=AEGEE,c=FR',
            attributes: {
              objectclass: ['person'],
              sn: x.last_name,
              uid: x.id,
              cn: x.first_name + x.last_name
            }
          };
        }).filter((x) => {
          return req.filter.matches(x.attributes);
        }).map((x) => {
          res.send(x);
        })

        request_more_members(offset + 250, previous_results)
      }
      else {
        // If there are no more results, end sending stuff
        res.end()
      }
    })
  }

  console.log("Requesting members database, start processing")
  request_more_members(0, []);
});

server.bind("", function (req, res, next) {
  var username = req.dn.toString(), // will be like cn=admin@aegee.org
      password = req.credentials.trim();  // will be like 1234password
  var username_parsed = username.match(/cn=([^\s,]*)/);
  // if the dn wasn't actually in that format, return a creative error...
  if(username_parsed.length < 2) {
    return next(new ldap.UnwillingToPerformError());
  }
  username_parsed = username_parsed[1];

  request({
    url: config.server.url + config.server.login_route,
    method: 'POST',
    json: true,
    body: {username: username_parsed, password: password}
  }, (error, foreign_res, body) => {
    if(error) {
      console.log("Could not contact MyAEGEE server")
      console.log(error)

      return next(new ldap.UnavailableError())
    }

    if(foreign_res.statusCode == 422) {
      return next(new ldap.InvalidCredentialsError())
    }

    if(!body.success) {
      return next(new ldap.OtherError())
    }

    logged_in_users[username] = {acc: body.access_token, ref: body.refresh_token, t: Date.now()}

    console.log("Successful login by " + username)

    res.end()
    return next()
  })
});

server.listen(1389, function() {
  console.log('LDAP server listening at %s', server.url);
});