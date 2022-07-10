//jshint esversion:6

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const findOrCreate = require('mongoose-find-or-create')
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;


const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//this has to do with sessions
passport.serializeUser(function(user, cb) {
    cb(null, user);
  });

  passport.deserializeUser(function(obj, cb) {
    cb(null, obj);
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id, username: profile.emails[0].value
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
  res.render("home");
});


app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile","email"] }));
  

  app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });
  
  
app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
if(err){
    console.log(err)
}else{
    res.render("secrets", {usersWithSecrets: foundUsers});
}
  });
});


app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

//to handle post submission from submit.ejs
app.post("/submit", function(req,res){
    const submittedSecret = req.body.secret;
    
    

    User.findById(req.user._id, function(err, foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save(function(){
                res.redirect("/secrets");
            });
            
        }
        }
    });

});

app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    }
  });
  res.redirect("/");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.listen(3000, () => {
  console.log("Server started on port 3000");
});
