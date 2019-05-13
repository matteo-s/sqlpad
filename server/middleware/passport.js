const passport = require('passport')
const PassportLocalStrategy = require('passport-local').Strategy
const PassportGoogleStrategy = require('passport-google-oauth20').Strategy
const OAuth2Strategy = require('passport-oauth2').Strategy

const BasicStrategy = require('passport-http').BasicStrategy
const User = require('../models/User.js')
const configUtil = require('../lib/config')
const db = require('../lib/db')
const checkWhitelist = require('../lib/check-whitelist.js')
const {
  baseUrl,
  googleClientId,
  googleClientSecret,
  publicUrl,
  oauthAuthorizationUrl,
  oauthTokenUrl,
  oauthUserInfoUrl,
  oauthClientId,
  oauthClientSecret,
  disableUserpassAuth
} = require('../lib/config').getPreDbConfig()

passport.serializeUser(function(user, done) {
  done(null, user.id)
})

passport.deserializeUser(function(id, done) {
  return User.findOneById(id)
    .then(user => {
      if (user) {
        return done(null, {
          id: user._id,
          _id: user._id,
          role: user.role,
          email: user.email
        })
      }
      done(null, false)
    })
    .catch(error => done(error))
})

if (!disableUserpassAuth) {
  passport.use(
    new PassportLocalStrategy(
      {
        usernameField: 'email'
      },
      function passportLocalStrategyHandler(email, password, done) {
        return User.findOneByEmail(email)
          .then(user => {
            if (!user) {
              return done(null, false, { message: 'wrong email or password' })
            }
            return user.comparePasswordToHash(password).then(isMatch => {
              if (isMatch) {
                return done(null, {
                  id: user._id,
                  _id: user._id,
                  role: user.role,
                  email: user.email
                })
              }
              return done(null, false, { message: 'wrong email or password' })
            })
          })
          .catch(error => done(error))
      }
    )
  )

  passport.use(
    new BasicStrategy(function(username, password, callback) {
      return User.findOneByEmail(username)
        .then(user => {
          if (!user) {
            return callback(null, false)
          }
          return user.comparePasswordToHash(password).then(isMatch => {
            if (!isMatch) {
              return callback(null, false)
            }
            return callback(null, user)
          })
        })
        .catch(error => callback(error))
    })
  )
}

if (googleClientId && googleClientSecret && publicUrl) {
  passport.use(
    new PassportGoogleStrategy(
      {
        clientID: googleClientId,
        clientSecret: googleClientSecret,
        callbackURL: publicUrl + baseUrl + '/auth/google/callback',
        // This option tells the strategy to use the userinfo endpoint instead
        userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo?alt=json'
      },
      passportGoogleStrategyHandler
    )
  )
}

if (oauthAuthorizationUrl && 
  oauthTokenUrl &&
  oauthUserInfoUrl &&
  oauthClientId &&
  oauthClientSecret && publicUrl) {
    passport.use(new OAuth2Strategy(
      {
        authorizationURL: oauthAuthorizationUrl,
        tokenURL: oauthTokenUrl,
        userInfoURL: oauthUserInfoUrl,
        clientID: oauthClientId,
        clientSecret: oauthClientSecret,
        callbackURL: publicUrl + baseUrl + '/auth/oauth/callback',
      },
      passportOAuthStrategyHandler
    )
  )
}

function passportGoogleStrategyHandler(
  accessToken,
  refreshToken,
  profile,
  done
) {
  const email = profile && profile._json && profile._json.email

  if (!email) {
    return done(null, false, {
      message: 'email not provided from Google'
    })
  }

  return Promise.all([
    User.adminRegistrationOpen(),
    User.findOneByEmail(email),
    configUtil.getHelper(db)
  ])
    .then(data => {
      let [openAdminRegistration, user, config] = data
      if (user) {
        user.signupDate = new Date()
        return user.save().then(newUser => {
          newUser.id = newUser._id
          return done(null, newUser)
        })
      }
      const whitelistedDomains = config.get('whitelistedDomains')
      if (openAdminRegistration || checkWhitelist(whitelistedDomains, email)) {
        user = new User({
          email,
          role: openAdminRegistration ? 'admin' : 'editor',
          signupDate: new Date()
        })
        return user.save().then(newUser => {
          newUser.id = newUser._id
          return done(null, newUser)
        })
      }
      // at this point we don't have an error, but authentication is invalid
      // per passport docs, we call done() here without an error
      // instead passing false for user and a message why
      return done(null, false, {
        message: "You haven't been invited by an admin yet."
      })
    })
    .catch(error => done(error, null))
}

function passportOAuthStrategyHandler(
  accessToken,
  refreshToken,
  profile,
  done
) {

  const email = profile && profile.email;

  if (!email) {
    return done(null, false, {
      message: 'email not provided from OAuth2 provider'
    })
  }


  return Promise.all([
    User.adminRegistrationOpen(),
    User.findOneByEmail(email),
    configUtil.getHelper(db)
  ])
    .then(data => {
      let [openAdminRegistration, user, config] = data

      if (user) {
        user.signupDate = new Date()
        return user.save().then(newUser => {
          newUser.id = newUser._id
          return done(null, newUser)
        })
      }


      const whitelistedDomains = config.get('whitelistedDomains')
      if (openAdminRegistration || checkWhitelist(whitelistedDomains, email)) {
        user = new User({
          email,
          role: openAdminRegistration ? 'admin' : 'editor',
          signupDate: new Date()
        })
        return user.save().then(newUser => {
          newUser.id = newUser._id
          return done(null, newUser)
        })
      }
      // at this point we don't have an error, but authentication is invalid
      // per passport docs, we call done() here without an error
      // instead passing false for user and a message why
      return done(null, false, {
        message: "You haven't been invited by an admin yet."
      })
    })
    .catch(error => done(error, null))
}

//extend oauth strategy for userInfo
OAuth2Strategy.prototype.userProfile = function (accessToken, done) {

  this._oauth2._useAuthorizationHeaderForGET = true;
  this._oauth2.get(oauthUserInfoUrl, accessToken, (err, body) => {
    if (err) {
      return done(err);
    }

    try {
      const json = JSON.parse(body);
      const email = json.email;
      const userInfo = {
        id: json.sub,
        username: json.preferred_username,
        email,
        _json: json
      };

      done(null, userInfo);
    } catch (e) {
      done(e);
    }
  });
};