const User=require('../models/users');
const jwt=require('jwt-simple');
const config=require('../config');

function tokenForUser(user){
    const timestamp=new Date().getTime();
    return jwt.encode({sub:user.id,iat:timestamp},config.secret);
}

exports.signup=function(req,res,next){
    const email=req.body.email;
    const password=req.body.password;
    if(!email || !password){
        return res.status(422).send({'error':'you must provide user and password'}); 
    }
   //see if user with the given email exists
    User.findOne({email:email},function(err,existingUser){
        if(err){ return next(err);  }
        //if a user a with email does exist then return an error
        if(existingUser){
            return res.status(422).send({'error':'Email is in use'});
        }
        //if a user does not exist and then create/save user record
        const user = new User({ email:email,
                             password:password
                        });
        user.save(function(err){
            if(err){return next(err);}
             //response to request indicating the user was created
             res.json(tokenForUser(user));
        });
    });  
}

exports.signin=function(req,res,next){
    //User and password authenticated using local strategy middleware
    //send the JWT strategy token back to use to continue using other protected resources
    res.json(tokenForUser(req.user));
}