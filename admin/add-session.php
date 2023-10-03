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
    $title = filter_var($_POST["title"], FILTER_SANITIZE_SPECIAL_CHARS);
    $docid = filter_var($_POST["docid"], FILTER_VALIDATE_INT);
    $nop = filter_var($_POST["nop"], FILTER_VALIDATE_INT);
    $date = filter_var($_POST["date"], FILTER_SANITIZE_SPECIAL_CHARS);
    $time = filter_var($_POST["time"], FILTER_SANITIZE_SPECIAL_CHARS);

    if ($docid && $nop && $title && $date && $time) {
        // Use prepared statements to insert data safely
        $stmt = $database->prepare("INSERT INTO schedule (docid, title, scheduledate, scheduletime, nop) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("issii", $docid, $title, $date, $time, $nop);

        if ($stmt->execute()) {
            header("location: schedule.php?action=session-added&title=" . urlencode($title));
            exit;
        } else {
            // Handle the database error gracefully
            $error = "Database error: " . $stmt->error;
        }
    } else {
        $error = "Invalid input data";
    }
}
