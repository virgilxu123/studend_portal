<?php
    // Initialize the session
    session_start();
    // Check if the user is already logged in, if yes then redirect him to welcome page
    if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
        header("location: welcome.php");
        exit;
    }
    // Include config file
    require_once "config.php";
    // Define variables and initialize with empty values
    $firstname = $lastname = $studentid = $password = $yearlevel = $block = "";
    $firstname_err = $lastname_err = $studentid_err = $password_err = $yearlevel_err = $block_err = $login_err = $idlogin_err = $pwlogin_err = "";

    if($_SERVER["REQUEST_METHOD"] == "POST"){
        if($_POST['submit']=="Sign up") {
            // Validate firstname
            if(empty($_POST["firstname"])){
                $firstname_err = "*";
            }elseif(!preg_match('/^[a-zA-Z0-9_]+$/', trim($_POST["firstname"]))){
                $firstname_err = "Invalid input"; 
            }else {
                $firstname = trim($_POST["firstname"]);
            }
            // Validate lastname
            if(empty($_POST["lastname"])){
                $lastname_err = "*";
            }elseif(!preg_match('/^[a-zA-Z0-9_]+$/', trim($_POST["lastname"]))){
                $lastname_err = "invalid input"; 
            }else {
                $lastname = $_POST["lastname"];
            }
            // Validate studentid            
            if(empty($_POST["studentid"])) {
                $studentid_err = "*";
            }elseif(!is_numeric(trim($_POST["studentid"]))){    
                $studentid_err = "invalid input"; 
            }else {
                //Prepare a select statement
                $sql = "SELECT studentid FROM studentstd WHERE studentid = ?";
                if ($stmt = $conn->prepare($sql)) {
                    // Bind variables to the prepared statement as parameters
                    $stmt->bind_param("s", $param_studentID);
                    // Set parameters
                    $param_studentID = trim($_POST["studentid"]);
                    // Attempt to execute the prepared statement
                    if ($stmt->execute()) {
                        /* store result */
                        $stmt->store_result();
                        if ($stmt->num_rows() == 1) {
                            $studentid_err= "Student ID already exist!";
                        } else {
                            $studentid = trim($_POST["studentid"]);
                        }
                    } else {
                        echo "Oops! Something went wrong. Please try again later.";
                    }
                    //Close statement
                    $stmt->close();
                }
            }
            // Validate password
            if(empty($_POST["password"])) {
                $password_err = "*";
            }elseif(strlen(trim($_POST["password"])) < 6) {
                $password_err = "Must have at least 6 characters";
            }else {
                $password = $_POST["password"];
                $password = password_hash($password, PASSWORD_DEFAULT);
            }
            // Validate yearlevel
            if(empty($_POST["yrlevel"])) {
                $yearlevel_err = "*";
            }else {
                $yearlevel = $_POST["yrlevel"];
            }
            // Validate block
            if(empty($_POST["block"])) {
                $block_err = "*";
            }else {
                $block = $_POST["block"];
            }

            if(empty($firstname_err)&&empty($lastname_err)&&empty($password_err)&&empty($studentid_err)&&empty($yearlevel_err)&&empty($block_err)){
                // prepare an insert statement
                $stmt = $conn->prepare("INSERT INTO studentstd (firstname, lastname, studentid, password, yearlevel, block) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->bind_param("ssssss", $firstname, $lastname, $studentid, $password, $yearlevel ,$block);
                $stmt->execute();
            }
        }        
        if($_POST["submit"]=="Log in") {
                // Check if studentid is empty
            if(empty(trim($_POST["studentid"]))) {
                $idlogin_err = "Please enter studentid";
            } else{
                $studentid = trim($_POST["studentid"]);
            }
            // Check if password is empty
            if(empty(trim($_POST["password"]))){
                $pwlogin_err = "Please enter your password.";
            } else{
                $password = trim($_POST["password"]);
            }
            // Validate credentials
            if(empty($idlogin_err) && empty($pwlogin_err)){
                // Prepare a select statement
                $sql = "SELECT studentid, firstname, password FROM studentstd WHERE studentid = ?";
                if($stmt = $conn->prepare($sql)){
                    // Bind variables to the prepared statement as parameters
                    $stmt->bind_param("s", $param_studentid);
                    // Set parameters
                    $param_studentid = trim($_POST["studentid"]);
                    // Attempt to execute the prepared statement
                    if($stmt->execute()){
                        // Store result
                        $stmt->store_result();
                        // Check if username exists, if yes then verify password
                        if($stmt->num_rows() == 1){
                            // Bind result variables
                            $stmt->bind_result($studentid, $firstname, $hashed_password);
                            if($stmt->fetch()){
                                if(password_verify($password, $hashed_password)){
                                    // Password is correct, so start a new session
                                    session_start();
                                    // Store data in session variables

                                    $_SESSION["loggedin"] = true;
                                    $_SESSION["id"] = $studentid;
                                    $_SESSION["name"] = $firstname;
                                    // Redirect user to welcome page
                                    header("location: welcome.php");
                                } else{
                                    // Password is not valid, display a generic error message
                                    $login_err = "Invalid username or password.";
                                }
                            }
                        } else{
                            // Username doesn't exist, display a generic error message
                            $login_err = "Student ID not yet register.";
                        }
                    } else{
                    echo "Oops! Something went wrong. Please try again later.";
                    }
                    // Close statement
                    $stmt->close();
                }
            }
            // Close connection
            $conn->close();
        } 
    }
    
    
    
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign Up</title>
    <link rel="stylesheet" href="styles\loginRegister.css">
    <style>
    </style>
</head>
<body>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>" method="post" >
        <div class="navbar">
            <div class="logo">
                <img src="images/ACCSlconNavigation.png" alt="">
            </div>
            <div class="login">
                <div>
                    <label for="studentid">Student ID:</label>
                    <input type="text" name="studentid" >
                    <span><?php echo  $idlogin_err; ?></span>
                </div>
                <div>
                    <label for="password">Password:</label>
                    <input type="password" name="password">
                    <span><?php echo  $pwlogin_err; ?></span>
                </div>
                <input type="submit" name="submit" value="Log in" class="btn1">
            </div>
            <span><?php echo $login_err; ?></span>
        </div>
    </form>
    <div class="main">
        <div class="left">
            <div class="lefttop">
                <div class="logo2">
                    <img src="images/BSCSLogo (1).png" alt="">
                </div>
                <p>Association of Computer Science Students</p>
            </div>
            <div class="leftbot">
                <p>College of Information Technology Education</p>
                <p style="font-size: 20px;font-weight:300;">NEMSU Tandag Campus</p>
            </div>
        </div>
        <div class="contRegister">
            <div class="register">
                <h2>Create an Account</h2>
                <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">
                    <div class="top">
                        <input type="text" name="firstname" placeholder="First Name">
                        <span class="error"><?php echo $firstname_err; ?></span>
                        <input type="text" name="lastname" placeholder="Last Name">
                        <span class="error"><?php echo $lastname_err; ?></span>
                    </div>   
                    <div class="info">
                        <input  type="text" name="studentid" placeholder="Student ID">
                        <span class="error"><?php echo $studentid_err; ?></span>
                        <input  type="password" name="password" placeholder="Passsword">
                        <span class="error"><?php echo $password_err; ?></span>
                        <input  type="text" name="yrlevel" placeholder="Year Level">
                        <span class="error"><?php echo $yearlevel_err; ?></span>
                        <input  type="text" name="block" placeholder="Block">
                        <span class="error"><?php echo $block_err; ?></span>
                    </div>
                    <input type="submit" name="submit" value="Sign up" class="btn2">
                </form> 
            </div>
        </div>
    </div>
</body>
</html>