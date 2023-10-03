<?php
session_start();

if (!isset($_SESSION["user"]) || $_SESSION["user"] === "" || $_SESSION['usertype'] !== 'a') {
    header("location: ../login.php");
    exit; // Terminate script execution after redirection
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Import database
    require_once("../connection.php");

    // Sanitize and validate input data
    $name = filter_var($_POST['name'], FILTER_SANITIZE_SPECIAL_CHARS);
    $nic = filter_var($_POST['nic'], FILTER_SANITIZE_SPECIAL_CHARS);
    $oldemail = filter_var($_POST["oldemail"], FILTER_VALIDATE_EMAIL);
    $spec = filter_var($_POST['spec'], FILTER_VALIDATE_INT);
    $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    $tele = filter_var($_POST['Tele'], FILTER_SANITIZE_SPECIAL_CHARS);
    $password = $_POST['password'];
    $cpassword = $_POST['cpassword'];
    $id = filter_var($_POST['id00'], FILTER_VALIDATE_INT);

    if ($password == $cpassword) {
        $error = '3';

        // Check if the new email already exists for another doctor
        $stmt = $database->prepare("SELECT docid FROM doctor WHERE docemail = ? AND docid != ?");
        $stmt->bind_param("si", $email, $id);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $error = '1';
        } else {
            // Hash the password securely
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            // Update doctor information
            $stmt = $database->prepare("UPDATE doctor SET docemail = ?, docname = ?, docpassword = ?, docnic = ?, doctel = ?, specialties = ? WHERE docid = ?");
            $stmt->bind_param("ssssssi", $email, $name, $hashedPassword, $nic, $tele, $spec, $id);

            if ($stmt->execute()) {
                // Update webuser email
                $stmt = $database->prepare("UPDATE webuser SET email = ? WHERE email = ?");
                $stmt->bind_param("ss", $email, $oldemail);
                $stmt->execute();

                $error = '4';
            } else {
                // Handle the database error gracefully
                $error = 'Database error: ' . $stmt->error;
            }
        }
    } else {
        $error = '2';
    }
} else {
    $error = '3';
}

header("location: doctors.php?action=edit&error=" . $error . "&id=" . $id);
exit;
