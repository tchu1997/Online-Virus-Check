<?php
// Name of the database: midterm2
// Name of the tables: admin, malwares

echo <<<_END
<html>
<head><title>Online Virus Check</title>
</head>
<body>
<form method="post" action="main.php" enctype="multipart/form-data">
<fieldset>
    <legend>Input File Form (User)</legend>
    <label>Upload a file to check</label>
    
    <input type="file" name="filename" size="10">
    <input type="submit" name="button" value="Check"><br><br>
    
    <input type="submit" name="button" value="Admin Login">
</form>
_END;
define("SALT1","qm&h*");
define("SALT2","pg!@");

require_once 'login.php';
$conn = new mysqli($hn,$un,$pw,$db); // connect to mysql db
if ($conn->connect_error){ 
    my_error("unable to connect to the database");
}else{ // if successfully connect to db
    // Set up admin info in the database (username: admin, password: 12345)
    setup_admin_info($conn);
    if ($_SERVER['REQUEST_METHOD'] == 'POST'){
        // 1. Check if the uploaded file contains a virus
        if ($_POST['button'] == "Check"){
            $filename = $_FILES["filename"]["name"];
            $type = $_FILES["filename"]["type"];
            $extension = pathinfo($filename, PATHINFO_EXTENSION);
            if ($type == "text/plain" && $extension == "txt"){
                get_input_file($conn,$filename); 
            }
            else{
                my_error("'$filename' is not accepted as a text file");
            }
        }
        // 2. Go to another page if user decides to login as an admin to upload a Malware file
        if ($_POST['button'] == "Admin Login"){
            $conn->close();
            header("Location: admin.php");
            exit;
        }
    }
    $conn->close();
    
}

/**************************************************************************
********************************FUNCTIONS**********************************
***************************************************************************/

// This function asks the user to enter his username and password
// if his username and password match with the ones in the database (so he is an admin),
// redirect him to an admin page where he can upload a Malware file.
// If the user provides wrong username/password or does not provide anything at all,
// prompt an error message.
function http_authentication($conn){
    if(isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])){
        if(isAdmin($conn,$_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])){
            header("Location: upload4.php"); // redirect to an admin page
            exit;
        }
        else{
            my_error("Invalid username or password");
        }
       
    }else{
        header('WWW-Authenticate: Basic realm="Restricted Section"');
        header('HTTP/1.0 401 Unauthorized');
        my_error("Without a valid username and password, you cannot upload a Malware file");
        die;
    }
}
// This function creates an admin account and save it to the database whenever the web page is open.
// Therefore, there should always be an username and password in the database.
// In the case the admin info already exists in the database ( this happens when an admin account is already created and the page is opened the 2nd time),
// then we don't need to create a new one.
// In conclusion: there should always be one admin account for this application, unless someone
// decides to change the two variables $username and $password after the first admin info is successfully created.
// Then, there will be two admin accounts, and possibly more if those two variables get changed frequently.
function setup_admin_info($conn){
    // Use this info to login as admin
    $username = "admin";
    $password = "12345";
    // Hash the password
    $hashedPassword = SALT1.$password.SALT2;
    $token = hash('ripemd128',"$hashedPassword");
    $query = "DESCRIBE admin";
    $result = $conn->query($query);
    // If the table for admin does not exists, create it
    if (!$result){
        $query = "CREATE TABLE admin(
                    username VARCHAR(32) NOT NULL UNIQUE,
                    password VARCHAR(32) NOT NULL
                )";
        $result = $conn->query($query);
        if (!$result){
            my_error("Unable to set up the database");
        }
    }
    // If the table for admin exists, check if username "admin" and password "12345" already exist
    // If they exist, do nothing. If they don't, add them to the table.
    if($result){
        if(!isAdmin($conn,$username,$password)){
            $query = "INSERT INTO admin VALUES ('$username','$token')";
            $result = $conn->query($query);
            if(!$result){
                my_error("Unable to insert admin info into the database");
            }
        }
    }
}

// Get uploaded file and check if it contains a virus
function get_input_file($conn,$filename){
    // if a file is uploaded, save it to the directory and perform a check
    if(!empty($filename)){
        move_uploaded_file($_FILES["filename"]["tmp_name"], $filename);                
        $content = preg_replace('/\s/', '', file_get_contents($filename)); // remove all white spaces in the file
        check($conn,$content);
     }
         // display an error if the user hits "Check" but no file is selected
    else{
        my_error("Unable to complete the requested task because you have yet selected a file");
    }   
    
}

// This function checks if the given username and password match with 
// the username and password of an admin in the database.
// Returns TRUE if they match or FALSE otherwise.
function isAdmin($conn,$un,$pw){
    $query = "SELECT * FROM admin where username='$un'";
    $result = $conn->query($query);
    if($result){
        $rows = $result->num_rows;
        if ($rows > 0){
            $row = $result->fetch_array(MYSQLI_NUM);
            $result->close();
            
            $password = SALT1.$pw.SALT2;
            $token = hash('ripemd128',"$password");
            if($token == $row[1]){ // if password is correct, return true
                return true;
            }
        }
    }
    // if username/password is incorrect, return false
    return false;
}

// This perfunction perform a check on the uploaded file
//  to see if it contains a virus
function check($conn,$content){
    // get data (of the Malware files) from the database
    $query = "SELECT * from malwares";
    $result = $conn->query($query);
    if(!$result){
        my_error("Unable to select records from database");
    }else{
        $rows = $result->num_rows;
        $isInfected = false;
        if ($rows > 0){
            for($i = 0; $i < $rows; $i++){ // go through the content of each Malware file
                $result->data_seek($i);
                $row = $result->fetch_array(MYSQLI_NUM);                          
                if(stripos($content,$row[2])!==false){ // check if the content of the uploaded file contains
                    $isInfected = true;                // a string from 1 of the Malware files 
                    break;
                }
            }
            if ($isInfected){
                echo "Oh no! We have found that this file contains a virus.";
            }
            else{
                echo "Everything seems safe. We have yet found a virus in this file.";
            }
        }else{
            echo "Sorry, we could not perform a check because there are currently no resources provided.";
        }
        $result->close();
    }
}

// This function customizes an error message,
function my_error($msg){
    echo <<<_END
    $msg.</br>
    Please try again. Thank you.</br>
    _END;
    
}
?>
