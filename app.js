//jshint esversion:6
require("dotenv").config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport'); //level - 4 security (Authentications and session with cookies.)
const passportLocalMongoose = require('passport-local-mongoose');
//const bcrypt = require('bcrypt'); // level-3 security ..hashing passwords with some salt and muliple salt rounds.
//const md5 = require("md5"); // used for hashing passwords (Level-2 Security)
//const encrypt = require('mongoose-encryption'); //Used for Encrypting passwords(level-1 security)
//const saltRounds = 10;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(bodyParser.urlencoded( {extended : true}));
app.set('view engnie','ejs');
app.use(express.static('public'));
app.use(session({
    secret: process.env.EXPRESS_SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  }));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.MONGO_URI,{
    useNewUrlParser : true,
    useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
    username: String,
    password : String,
    googleId : String,
    facebookId : String,
    secret : String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//const secret = process.env.SECRET;
//userSchema.plugin(encrypt , {secret : secret, encryptedFields : ["password"]});

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
/*passport.use(new LocalStrategy({
    passReqToCallback: true
    }, function (req, username, password, done) {
         var email = req.body.email;
    }));*/ 

//this serialization works only for local serialization.
/*passport.serializeUser(User.serializeUser()); // to serialize means - creating cookie and stuffing it up with session credentials.
passport.deserializeUser(User.deserializeUser());*/

//to make serialization work for all kind of authentication we use serialization given on passport.js documentation.
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      console.log(profile);

      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
    res.render("home.ejs");
});

//On google servers authentication(uses google strategy defined above).
app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] }));

//Once Authenticated on google servers, we get rediected to this route and authenticate the user on our server to create session for his/her browsing session.
app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }), //.authenticate uses serialize to create session for user.
  function(req, res) {
    // Successful authentication, redirect secrets(basically let user enter the app).
    console.log("going to secrets");
    res.redirect("/secrets");
  });


app.get("/auth/facebook",
  passport.authenticate('facebook'));


app.get("/auth/facebook/secrets",
  passport.authenticate('facebook', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect into the app(secrets here).
    res.redirect("/secrets");
});

app.get("/login",function(req,res){
    res.render("login.ejs");
});

app.get("/secrets",function(req,res){
    if(req.isAuthenticated()){
        console.log("Authenticated");
        res.render("secrets.ejs");
    }else{
        console.log("Not authenticated");
        res.redirect("/login");
    }
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit.ejs");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit",function(req,res){
    const secret = req.body.secret;
    const user_id = req.user.id;
    User.findById(user_id, function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = secret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                })
            }
        }
    });
    
})

app.post("/login",function(req,res){
    /*const email = req.body.email;
    const password = req.body.password; */
    //const password = md5(req.body.password);
    /*console.log(req);
    console.log(email);
    console.log(password);*/

    /*User.findOne({email : email},function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                bcrypt.compare(password, foundUser.password, function(err, result) {
                    if(result === true){
                        res.render("secrets.ejs");
                    }else{
                        console.log("Sorry! Wrong password");
                    }
                });
            }else{
                console.log("User Doesn't Exists");
            }
        }
    });*/

    //Now Using Passport.js

    const newUser = new User({
        username : req.body.username,
        password : req.body.password
    });

    req.login(newUser, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

});

app.get("/register",function(req,res){
    res.render("register.ejs");
});

app.post("/register",function(req,res){

    /*bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser = new User({
            username : req.body.username,
            email : req.body.email,
            password : hash
        });
    
        newUser.save(function(err){
            if(!err){
                res.redirect("/login");
            }else{
                console.log(err);
            }
        });    
    });*/

    //now using passport.js
    User.register({username : req.body.username, active :false}, req.body.password, function(err,user){
        if(err){
            console.log(error);
            res.redirect("/register");
        }else{
            res.redirect("/login");
        }
    })
    
    
});


app.listen('3000',function(){
    console.log("App started on port 3000");
});

app.get("/logout",function(req,res){
    req.logout();   //uses deserialize to vlear the cookie or session created for user.
    res.redirect("/");
});