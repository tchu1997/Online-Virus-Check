<?php
define("SALT1","qm&h*");
define("SALT2","pg!@");

require_once 'login.php';
$conn = new mysqli($hn,$un,$pw,$db); // connect to mysql db
if ($conn->connect_error){
    my_error("unable to connect to the database");
}else{
    login($conn);
    $conn->close();
}
/**************************************************************************
********************************FUNCTIONS**********************************
***************************************************************************/

// Prompt a http authentication to check if the user is an admin
// If the user is an admin, display a html form where he can upload a Malware file
// Otherwise, display an error message.
function login($conn){
      if(isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])){
        // case 1: if user is an admin  
        if(isAdmin($conn,$_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])){
            echo "You are now logged in as '".$_SERVER['PHP_AUTH_USER']."'";
            get_input_file($conn); // display html form for admin to upload a file
        }
        // case 2: if user is not an admin (wrong usename/password)
        else{
            my_error("Invalid username or password");
        }
       // case 3: if no username/password is provided
    }else{
        header('WWW-Authenticate: Basic realm="Restricted Section"');
        header('HTTP/1.0 401 Unauthorized');
        my_error("Without a valid username and password, you cannot upload a Malware file");
        die;
    }
}

// Display a html form where an admin can upload a Malware file
// Save the first 20 bytes of that file into the database (with no white spaces)
function get_input_file($conn){
    echo <<<_END
    <html>
    <head><title>Online Virus Check</title>
    </head>
    <body>
    <form method="post" action="admin.php" enctype="multipart/form-data">
    <fieldset>
    <legend>Input File Form (Admin)</legend>
    <label>Name of the Malware</label>
    <input type="text" name="name"></br>
    <label>Upload the Malware</label>
    <input type="file" name="filename" size="10">
    <input type="submit" name="button" value="Upload"><br>
    </fieldset>
    </form></body></html>
    _END;
    if ($_SERVER['REQUEST_METHOD'] == 'POST'){
        // case 1: if a file is uploaded, insert it into the database
        if(!empty($_FILES['filename']['name']) && $_POST['name']!=''){
            $name = get_post($conn,'name');
            $filename = $_FILES['filename']['name'];
            $type = $_FILES['filename']['type'];
            $extension = pathinfo($filename, PATHINFO_EXTENSION);
            if ($type == "text/plain" && $extension == "txt"){
                move_uploaded_file($_FILES['filename']['tmp_name'], $filename);
                // remove all white spaces then get first 20 bytes
                $content = preg_replace('/\s/', '', file_get_contents($filename,NULL,NULL,0,20));
                $content = sanitize_file_content($conn,$content); 
                insert($conn,$name,$content);
            }
            else{
                my_error("'$filename' is not accepted as a text file");
            }
        }
        // case 2: if user does not select a file and/or provide a name, prompt an error msg
        else 
        {
             my_error("Unable to complete the requested task because you left the name blank or have yet selected a file");
        }     
    }
}

// Insert first 20 bytes (with no white spaces) of the uploaded file into the database
function insert($conn,$filename,$content){
    $query = "DESCRIBE malwares";
    $result = $conn->query($query); // first, check if the 'malwares' table exists
                                    // if it doesn't, create it.
    if(!$result){ 
        $query = "CREATE TABLE malwares(
                id INT(4) UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                Name VARCHAR(50) NOT NULL,
                Content CHAR(20) NOT NULL UNIQUE
        )";
        $result = $conn->query($query);
        if(!$result){
            my_error("Unable to set up the database");
        }
    }
    // At this point, the 'malware' table should already exist.
    // Insert the uploaded file into this table.
    if($result){
        $query = "INSERT INTO malwares(Name, Content) VALUES ('$filename','$content')";
        $result = $conn->query($query);
        if(!$result){
            my_error("Unable to upload this Malware file. It might have already existed in the database");
         }
    }
}

// Check if the current user is an admin by comparing his
// username and password with the ones in the database.
// Returns true if he is an admin, otherwise false.
function isAdmin($conn,$un,$pw){
    $query = "SELECT * FROM admin where username='$un'";
    $result = $conn->query($query);
    if(!$result){
        my_error("Unable to find this data from database");
    }else{
        $rows = $result->num_rows;
        if ($rows > 0){
            $row = $result->fetch_array(MYSQLI_NUM);
            $result->close();
            
            $password = SALT1.$pw.SALT2; // add salt to the password
            $token = hash('ripemd128',"$password"); // hash the password
            if($token == $row[1]){ // if password is correct
                return true;
            }
        }
    }
    return false;
}

// To display friendly error msg
function my_error($msg){
    echo <<<_END
    $msg.</br>
    Please try again. Thank you.</br>
    _END;
    
}
// To sanitize the Malware's content
function sanitize_file_content($conn,$var){
    return mysqli_real_escape_string($conn,$var);
}

// To sanitize the Malware's name
function get_post($conn, $var){
    return $conn->real_escape_string($_POST[$var]);
}
?>