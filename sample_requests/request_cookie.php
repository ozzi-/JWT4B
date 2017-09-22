PHP Sending the request
<?php
    $c = curl_init('response_cookie.php');
    curl_setopt($c, CURLOPT_VERBOSE, 1);
    curl_setopt($c, CURLOPT_COOKIE, 'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ');
    curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);
    $page = curl_exec($c);
    curl_close($c);
?>
