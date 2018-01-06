const passport = require('passport');
const User=require('../models/users');
const config=require('../config');
const JwtStrategy=require('passport-jwt').Strategy;
const ExtractJwt=require('passport-jwt').ExtractJwt;
const LocalStrategy=require('passport-local');


//Set up options for JWT strategy
//options give details like where to look for JWT token in request body like url/header/body
//also JWT options provide scret key used for encoding the tokens

//Create a local strategy
const localOptions={'usernameField':'email'};
const localLogin=new LocalStrategy(localOptions,function(email,password,done){
    //verify username and password
    User.findOne({email:email},function(err,user){
        if(err){return done(err);}
        if(!user){ return done(null,false);}
        //compare incoming 'password' with database password as user exists
        user.comparePassword(password,function(err,isMatch){
            if(err) {return done(err);}
            if(!isMatch){return done(null,false);}
            return done(null,user);
        });
    })

});

//create JWT strategy
const jwtOptions={
    jwtFromRequest:ExtractJwt.fromHeader('authorization'),
    secretOrKey:config.secret
};
const jwtLogin=new JwtStrategy(jwtOptions,function(payload,done){
    //see if USERID exists in our database
    //if it does calll 'done with that user
    //otherwise, call done without a use object
    User.findById(payload.sub,function(err,user){
        if(err){return done(err,false)};
    if(user){
        done(null,user);
    }else{
        done(null,false);
    }
    });
});

//tell passport to use JWT strategy
passport.use(jwtLogin);
passport.use(localLogin);