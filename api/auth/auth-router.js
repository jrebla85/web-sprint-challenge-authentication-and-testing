const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const {jwtSecret} = require("../../config/secrets.js")
const Users = require('../users-model.js');
const {
  checkForDuplicates,
  checkPayload,
  checkUsernameExists,
} = require('../middleware/validate-user.js');

 

router.post('/register', checkPayload, checkForDuplicates, (req, res) => {

  let user = req.body;

  // bcrypting the password before saving
  const rounds = process.env.BCRYPT_ROUNDS || 8; // 2 ^ 8
  const hash = bcrypt.hashSync(user.password, rounds);

  // never save the plain text password in the db
  user.password = hash

  Users.add(user)
    .then(saved => {
      console.log("saved: ", saved)
      res.status(201).json(saved);
    })
    .catch(err => {
      res.status(500).json({
        message: `Error: ${err}`
      })
    }); 

});


router.post('/login', checkPayload, checkUsernameExists, (req, res) => {

  console.log("starting /login");
  let { username, password } = req.body;
  console.log("username: ", username)
  console.log("password ", password)
  Users.findByUserName(username) 
    .then((user) => {
      console.log("user.username", user.username);
      console.log("user.password", user.password);
      if (user && bcrypt.compareSync(password, user.password)) {
        console.log("credentials are correct")
        const token = makeToken(user)
        res.status(200).json({
            message: `welcome, ${user.username}`,
            token: token
        });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch((err) => {
      res.status(500).json(err)
    });
  
  });


  function makeToken(user){
    const payload = {
      subject:user.id,
      username:user.username
    }
    const options = {
      expiresIn: "500s"
    }
    return jwt.sign(payload,jwtSecret,options)
  }
  
  module.exports = router;
  
