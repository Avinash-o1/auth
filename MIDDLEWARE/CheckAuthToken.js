const jwt = require("jsonwebtoken");

const checkAuth = (req, res, next) => {
  const authToken = req.cookies.authToken;
  const refreshToken = req.cookies.refreshToken;

  if (!authToken || !refreshToken) {
    return res.status(403).json({ message: " Login Failed" });
  }
  jwt.verify(authToken, process.env.JWT_SECRET_KEY, (err, decoded) => { //check if authtoken is valid
    if (err) {
      jwt.verify(
        refreshToken,
        process.env.JWT_REFRESH_SECRET_KEY,
        (refErr, refDecoded) => { //check if refresh token is valid
          if (refErr) {
            return res.status(402).json({ message: " Authentication Failed" });
          } else { // if refresh token is valid create new auth and refresh tokens
            const newAuthToken = jwt.sign(
              { userId: refDecoded.userId },
              process.env.JWT_SECRET_KEY,
              { expiresIn: "10m" }
            );
            const newRefToken = jwt.sign(
              { userId: refDecoded.userId },
              process.env.JWT_REFRESH_SECRET_KEY,
              { expiresIn: "1d" }
            );
              // save tokens in cookies
            res.cookie("authToken", newAuthToken, { httpOnly: true });
            res.cookie("refreshToken", newRefToken, { httpOnly: true });

            req.userId = refDecoded.userId;
            next();
          }
        }
      );
    } else {
      req.userId = decoded.userId;
      next();
    }
  });
};

module.exports = checkAuth;
