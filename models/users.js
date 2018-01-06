const mongooose=require('mongoose');
const bcrypt=require('bcrypt-nodejs');
const Schema= mongooose.Schema;

//define our model
const userSchema=new Schema({
    email:{type:String,unique:true,lowercase:true},
    password:String
});


//On save hook , encrypt password
//before saving a model , run this function
userSchema.pre('save',function(next){
    //get access to user model
    const user=this;
    //generate a salt then run callback
    bcrypt.genSalt(10,function(err,salt){
        if (err){ return next(err)}
        //hash the password using the salt
        bcrypt.hash(user.password,salt,null,function(err,hash){
            if(err){return next(err)}
            //overwrite plaintext password with encrypted password
            user.password=hash;
            next();
        })
    })
})

//create a method instance on the userSchema object to comparePassword
userSchema.methods.comparePassword=function(candidatePassword,callback){
    bcrypt.compare(candidatePassword,this.password,function(err,isMatch){
        if(err) {return callback(err);}
        return callback(null,isMatch);
    });
};


//create the model class
const ModelClass=mongooose.model('user',userSchema);
//export the model
module.exports=ModelClass;