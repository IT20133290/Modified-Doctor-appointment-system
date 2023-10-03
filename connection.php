<?php

    $database= new mysqli("localhost","root","1010","edoc");
    if ($database->connect_error){
        die("Connection failed:  ".$database->connect_error);
    }
