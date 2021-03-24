const routes = require('express').Router();
const { 
    getUserOperations,
    createUserOperation,
    updateUserOperation,
    deleteUserOperation,
    loginUser,
    registerUser,
    checkToken
} = require('./queries');

routes.get('/operations', getUserOperations);
routes.post('/create-operation', createUserOperation);
routes.put('/update-operation', updateUserOperation);
routes.delete('/delete-operation', deleteUserOperation);

routes.post('/login', loginUser);
routes.post('/register', registerUser);
routes.post('/check-token/', checkToken);

module.exports = routes;