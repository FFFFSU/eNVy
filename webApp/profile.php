<?php

    if(isset($_POST['user_id']) && $_POST['user_id'] >= 1 && $_POST['user_id'] <= 2) {
        $userID = $_POST["user_id"];
        $name = ["", "Bob", "Anna"];
        $dob = ["", "19 February 1985", "25 August 1990"];
        $address = ["", "Orchid Blvd", "Long Ave"];
        $phoneNumber = ["", "500-515-290", "500-263-530"];
    } else {
        $userID = 0;
        $name = ["Not found"];
        $dob = ["Not found"];
        $address = ["Not found"];
        $phoneNumber = ["Not found"];
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile</title>
</head>
<body>
    <h1>Profile</h1>
    <ul>
        <li>Name: <?php echo $name[$userID] ?> </li>
        <li>Date of birth: <?php echo $dob[$userID] ?></li>
        <li>Address: <?php echo $address[$userID] ?></li>
        <li>Phone number: <?php echo $phoneNumber[$userID] ?></li>
    </ul>
</body>
</html>