require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require('mongoose-findorcreate') // (4)
                      /*---------- (1) -----------*/
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
                      /*---------- (1) -----------*/
const app = express();

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.set("view engine", "ejs");

//"local" strategy:
app.use(session({
  secret: process.env.LOCAL_SECRET,
  resave: false,
  saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());

/*------------------------------ Database ------------------------------------*/

//Connection:
const databaseUrl = "mongodb+srv://admin-amin:admin123@cluster0-nrrhg.mongodb.net/";
mongoose.connect(databaseUrl + 'userDB', {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true); // Removing the DeprecationWarning.
//Schema Creation:
const usersSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String,
  googleId: String,     // (3)
  facebookId: String    // (3)
});

usersSchema.plugin(passportLocalMongoose);
usersSchema.plugin(findOrCreate); // (5)

//Collection Creation:
const User = mongoose.model("User", usersSchema);

passport.use(User.createStrategy());

                        /*---------- (7) -----------*/
//Cookies:
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
                        /*---------- (7) -----------*/
                        /*---------- (2) -----------*/
//"Google" strategy:
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) { //requires nmp: mongoose-findorcreate
      return cb(err, user);
    });
  }
));

//"Facebook" strategy:
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
                        /*---------- (2) -----------*/

/*------------------------------ Home page -----------------------------------*/

app.get("/", function(req, res) {
  res.render("home.ejs");
});

/*------------------------------ Secrets page --------------------------------*/

app.get("/secrets", function(req, res) {

  User.find({secret: {$ne: null}}, function(err, data) {
    if (err) {
      console.log(err);
    } else {
      res.render("secrets", {
        allSecrets: data
      });
    }
  });
});
/*------------------------------ Submit a secret page ------------------------*/

app.route("/submit")

  .get(function(req, res) {
    if (req.isAuthenticated()) {
      res.render("submit.ejs");
    } else {
      res.redirect("/login");
    }
  })

  .post(function(req, res) {
    //req.user comes from passport packege.
    User.updateOne({_id: req.user._id}, {$set: {secret: req.body.secret}}, function(err) {
      if (err) {
        console.log(err);
      } else {
        res.redirect("/secrets");
      }
    })
  })
;
/*------------------------------ Logout page --------------------------------*/

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});
/*------------------------------ Register page -------------------------------*/

app.route("/register")

  .get(function(req, res) {
    res.render("register.ejs");
  })

  .post(function(req, res) {
    //Using "passport-local-mongoose" to Create user and save it inside the database.
    User.register({username: req.body.username}, req.body.password, function(err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    });
  })
;
/*------------------------------ (6) Google Routes ---------------------------*/

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  }
);
/*------------------------------ (6) Facebook Routes ---------------------------*/
app.get('/auth/facebook',
  passport.authenticate('facebook')
);

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  }
);
/*------------------------------ Login page ----------------------------------*/

app.route("/login")

  .get(function(req, res) {
    res.render("login.ejs");
  })

  .post(function(req, res) {

    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

    req.login(user, function(err){
      if (err) {
        console.log(err);
        res.redirect("/login");
      } else {
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    });
  })
;
/*------------------------------ Launch the server ---------------------------*/
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
};

app.listen(port, function() {
  console.log("Server has started successfully");
});
