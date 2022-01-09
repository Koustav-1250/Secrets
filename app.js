//jshint esversion:6
require('dotenv').config()
const express=require("express")
const bodyParser=require("body-parser")
const ejs=require("ejs")
const mongoose=require("mongoose")
//******************************************* */
// const encrypt=require("mongoose-encryption");
// const md5=require("md5");
// const bcrypt=require("bcrypt");       Different methods of authorisation
// const saltRounds=10;

//******************************************* */
const session=require("express-session") 
const passport=require("passport")
const passportLocalMongoose=require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate=require("mongoose-findorcreate");

// To-do task is to add Facebook authorisation as well.
const app=express()

app.set('view engine', 'ejs')
app.use(express.static("public"))
app.use(bodyParser.urlencoded({extended: true}))

// telling our app to use the session
app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());  // initializing passport and use passport
app.use(passport.session()); // tell our app to use passport for the dealing with session





mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true});

const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    username:String,
    secret:[]
});

 // To hash and salt the passwords and save the users to our database
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);



// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:['password']});


const User= mongoose.model("User",userSchema);


passport.use(User.createStrategy());

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
    callbackURL: "http://localhost:2000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ username: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/",function(req,res){
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));


app.get("/login",function(req,res){
    res.render("login");
});


app.get("/register",function(req,res){
    res.render("register");
});

app.get("/secrets",function(req,res){
  User.find({"secret":{$ne: null}},function(err,foundUser){
    if(err){
        console.log(err);
    }else{
        res.render("secrets",{users:foundUser})
    }
  })
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit",function(req,res){
    const submittedsecret=req.body.secret;
    const username=req.user.id;
    User.findById(username,function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret.push(submittedsecret);   
                foundUser.save(function(err){
                    if(err){
                        console.log(err);
                    }else{
                        res.redirect("/secrets");
                    }
                })  
            }
        }
    })
})

app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
});

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets page.
    res.redirect("/secrets");
  });

// whenever server is restarted cookies are deleted and session is restarted!!!


app.post("/register",function(req,res){

    User.register({username:req.body.username},req.body.password,function(err,User){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            }); 
        }

    })
});

app.post("/login",function(req,res){
    const user=new User({
        username:req.body.username,
        password:req.body.password
    })
    req.login(user,function(err){
        if(err){
            res.redirect("/login");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    })
});

app.listen("2000",function(){
console.log("Server Started at port 2000");
})