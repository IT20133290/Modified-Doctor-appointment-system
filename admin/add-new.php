<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../css/animations.css">
    <link rel="stylesheet" href="../css/main.css">
    <link rel="stylesheet" href="../css/admin.css">

    <title>Doctor</title>
    <style>
        .popup {
            animation: transitionIn-Y-bottom 0.5s;
        }
    </style>
</head>

<body>
    <?php
    session_start();

    // Check if the user is logged in as an admin
    if (!isset($_SESSION["user"]) || $_SESSION["user"] === "" || $_SESSION['usertype'] !== 'a') {
        header("location: ../login.php");
        exit; // Terminate script execution after redirection
    }

    // Include database connection
    require_once("../connection.php");

    $error = ''; // Initialize error message

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Sanitize and validate input data
        $name = filter_var($_POST['name'], FILTER_SANITIZE_SPECIAL_CHARS);
        $nic = filter_var($_POST['nic'], FILTER_SANITIZE_SPECIAL_CHARS);
        $spec = filter_var($_POST['spec'], FILTER_SANITIZE_SPECIAL_CHARS);
        $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
        $tele = filter_var($_POST['Tele'], FILTER_SANITIZE_SPECIAL_CHARS);
        $password = $_POST['password'];
        $cpassword = $_POST['cpassword'];

        if ($email && $password === $cpassword) {
            // Check if the email already exists
            $stmt = $database->prepare("SELECT * FROM webuser WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows == 1) {
                $error = 'Email already exists';
            } else {
                // Hash the password securely
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

                // Insert the new doctor into the database
                $stmt = $database->prepare("INSERT INTO doctor (docemail, docname, docpassword, docnic, doctel, specialties) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->bind_param("ssssss", $email, $name, $hashedPassword, $nic, $tele, $spec);
                $stmt->execute();

                // Insert the corresponding webuser entry
                $stmt = $database->prepare("INSERT INTO webuser (email, usertype) VALUES (?, 'd')");
                $stmt->bind_param("s", $email);
                $stmt->execute();

                $error = 'Registration successful';
            }
        } else {
            $error = 'Invalid data or passwords do not match';
        }
    }

    header("location: doctors.php?action=add&error=" . urlencode($error));
    exit; // Terminate script execution after redirection
    ?>
</body>

</html>