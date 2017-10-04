<?php
    echo("Responding with same token cookie . . . ");
    if(isset($_COOKIE['token'])){
        setcookie("token", $_COOKIE['token']);
    }
?>
