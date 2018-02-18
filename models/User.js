// Mongoose will be used to handle the database
var mongoose = require("mongoose");
var uniqueValidator = require("mongoose-unique-validator");
var crypto = require("crypto");

// creates here the schema of the model User with its attributes
// username and email have validations
var UserSchema = new mongoose.Schema({
  username: { type: String, lowercase: true,
    unique: true,
    required: [true, "cant be blank"],
    match: [/^[a-zA-Z0-9]+$/, 'is invalid'],
    index: true },
  email: { type: String, lowercase: true,
    unique: true,
    required: [true, "can't be blank"],
    match: [/\S+@\S+\.\S+/, 'is invalid'],
    index: true },
  bio: String,
  image: String,
  hash: String,
  salt: String
}, { timestamps: true});


// This line is to trigger the error when the validation on uniqueness fails
UserSchema.plugin(uniqueValidator, { message: 'is already taken.' });

// Password Methods
// Setting the password hash - using crypto to create a securised hash of the psw
// Method pbkdf2Sync() is taking 5 parameters (password to hash, salt used, nr of iterations, hash length, algorithm to be used)
UserSchema.methods.setPassword = function(password){
  this.salt = crypto.randomBytes(16).toString('hex');
  this.hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
};

// Validating password hash
UserSchema.methods.validatePassword = function(password) {
  var hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
  return this.hash === hash;
};

// This line registers the User model in Mongoose
// The model can be accessed then anywhere in the application by calling mongoose.model('User')
mongoose.model('User', UserSchema);
