<?php
        echo("Responding with same auth bearer . . . ");

        if(isset($_SERVER['HTTP_AUTHORIZATION'])){
                header("Authorization: ".$_SERVER['HTTP_AUTHORIZATION']);
        }
?>