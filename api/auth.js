const { authSecret } = require('../.env');
const jwt = require('jwt-simple');
const bcrypt = require('bcrypt-nodejs');

module.exports = app => {
  const signin = async (req, res) => {
    if (!req.body.email || !req.body.password) {
      return res.status(400).send('Dados incompletos');
    }

    const user = await app
      .db('users')
      .where({ email: req.body.email })
      .first();

    if (user) {
      bcrypt.compare(req.body.password, user.password, (err, isMatch) => {
        if (err || !isMatch) {
          res.status(401).send('Autenticação inválida');
        }

        const payload = { id: user.id };
        res.json({
          name: user.name,
          email: user.email,
          token: jwt.encode(payload, authSecret),
        });
      });
    } else {
      res.status(400).send('Usuário não cadastrado');
    }
  };

  return { signin };
};
