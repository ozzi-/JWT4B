<?php
        echo("Responding with same auth bearer . . . ");

        if(isset($_SERVER['HTTP_AUTHORIZATION'])){
                header("Authoriazion: ".$_SERVER['HTTP_AUTHORIZATION']);
        }
?>