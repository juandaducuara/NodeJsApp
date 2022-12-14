const express = require('express');
const {engine} = require('express-handlebars');
const myconnection = require('express-myconnection');
const mysql= require('mysql');
const session = require('express-session');
const bodyParser = require('body-parser');

const loginRoutes = require('./routes/login');

const app = express();
app.set('port',4000);

app.set('views', __dirname + '/views');
app.engine('.hbs',engine({
    extname:'.hbs',
}));

app.set('view engine','hbs');

app.use(bodyParser.urlencoded({
    extended:true
}));

app.use(bodyParser.json());

app.use(myconnection(mysql,{
    host:'localhost',
    user: 'root',
    port: 3307 ,
    database: 'creditoselbosque'
}))

app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized:true
}));

app.listen(app.get('port'),()=>{
    console.log('Lisning on port ' , app.get('port'));
});

app.use('/',loginRoutes);

app.get('/',(req,res)=>{
    if(req.session.loggedin==true){
        res.render('home', {empNombre:req.session.empNombre});
    }else{
        res.redirect('/login');
    }     
});