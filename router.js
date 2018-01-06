const Authentication=require('./controllers/authentication');
const passportService=require('./services/passport');
const passport=require('passport');

//middlware for authentication using JWT and local strategy
const requireAuth=passport.authenticate('jwt',{session:false});
const requireSignin=passport.authenticate('local',{session:false});


module.exports=function(app){
    app.get('/',requireAuth,function(req,res){
        res.send('Hi there');
    })
    app.post('/signin',requireSignin,Authentication.signin);
    app.post('/signup',Authentication.signup);
}