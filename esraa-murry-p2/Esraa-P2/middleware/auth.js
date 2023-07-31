import jwt from 'jsonwebtoken';
import config from 'config';

const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    const car = config.get('jwtCar');

    if(!token) {
        return res
            .status(401)
            .json({ message: 'Missing authentication token. Authorization failed'});
    }

    try{
        const decodedToken = jwt.verify(token, car);
        req.user = decodedToken.user;
        next();
    } catch (error){
        res
            .status(401)
            .json({ message: 'Invalid authentication token. Authorization failed'});
    }
};
export default auth;