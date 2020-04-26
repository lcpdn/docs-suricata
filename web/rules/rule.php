<!DOCTYPE html> <?php $servername = "localhost"; $username = "suricata"; $password = "SURICATA"; $dbname = "suricata_docs"; $sid = $_GET['sid']; $conn = new 
mysqli($servername, $username, $password, $dbname); if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
$sql = "select * from documentation where sid=".$sid; $result = $conn->query($sql); if ($result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
       $sid=$row["sid"];
		$name=$row["name"];
		$rule=$row["rule"];
		$file=$row["file"];
		$attack_target=$row["attack_target"];
		$description=$row["description"];
		$tag=$row["tag"];
		$affected_products=$row["affected_products"];
		$severity=$row["severity"];
		$signature_deployment=$row["signature_deployment"];
		$category=$row["category"];
		$url_reference=$row["url_reference"];
		$cve_reference=$row["cve_reference"];
		$creation_date=$row["creation_date"];
		$last_modified_date=$row["last_modified_date"];
		$rev=$row["rev"];
		$classtype=$row["classtype"];
		$severity=$row["severity"];
		$ruleset=$row["ruleset"];
		$malware_family=$row["malware_family"];
		$type=$row["type"];
    }
} else {
    echo "0 results";
}
$conn->close(); ?> <html lang="en"> <head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="description" content="">
  <meta name="author" content="">
  <title>Suricata Rule Infos</title>
  <!-- Custom fonts for this template-->
  <link href="vendor/fontawesome-free/css/all.min.css" rel="stylesheet" type="text/css">
  <link href="https://fonts.googleapis.com/css?family=Nunito:200,200i,300,300i,400,400i,600,600i,700,700i,800,800i,900,900i" rel="stylesheet">
  <!-- Custom styles for this template-->
  <link href="css/sb-admin-2.min.css" rel="stylesheet"> </head> <body id="page-top">
  <!-- Page Wrapper -->
  <div id="wrapper">
        <!-- Begin Page Content -->
        <div class="container-fluid">
          <!-- Page Heading -->
          <div class="d-sm-flex align-items-center justify-content-between mb-4">
            <h1 class="h3 mb-0 text-gray-800">Rule SID: <?php echo $sid;?></h1>
          </div>
          <div class="row">
 <div class="card mb-8">
                <div class="card-header">
                  <?php echo $name;?>
                </div>
                <div class="card-body">
                  <?php echo $rule;?>
                </div>
              </div>
			  <br>
          </div>
          <div class="row">
            <div class="col-lg-6">
              <!-- Default Card Example -->
              <div class="card mb-4">
                  <div class="card-header py-3">
                  <h6 class="m-0 font-weight-bold text-primary">Rule info</h6>
                </div>
                <div class="card-body">
                  <b> Creation date :</b><?php echo $creation_date;?><br>
				  <b> Last modified date :</b><?php echo $last_modified_date?><br>
				  <b> Version :</b><?php echo $rev;?><br>
				  <b> File :</b><?php echo $file;?><br>
				  <b> Ruleset :</b><?php echo $ruleset;?><br>
                </div>
              </div>
              <!-- Basic Card Example -->
              <div class="card shadow mb-4">
                <div class="card-header py-3">
                  <h6 class="m-0 font-weight-bold text-primary">Signature info</h6>
                </div>
                <div class="card-body">
                  <b> Attack target :</b><?php echo $attack_target;?><br>
				  <b> Affected products :</b><?php echo $affected_products?><br>
				  <b> Severity :</b><?php echo $severity;?><br>
				  <b> CVE Reference :</b><?php echo $cve_reference;?><br>
				  <b> Category :</b><?php echo $category;?><br>
                </div>
              </div>
            </div>
            <div class="col-lg-6">
			              <div class="card shadow mb-4">
                <div class="card-header py-3">
                  <h6 class="m-0 font-weight-bold text-primary">Description</h6>
                </div>
                <div class="card-body">
                  <?php echo $description;?>
                </div>
              </div>
			  <br>
              <div class="card shadow mb-4">
                <div class="card-header py-3">
                  <h6 class="m-0 font-weight-bold text-primary">More info</h6>
                </div>
                <div class="card-body">
                  <b> Performance impact :</b><?php echo $pe;?><br>
				  <b> Classtype :</b><?php echo $classtype?><br>
				  <b> Type :</b><?php echo $type;?><br>
				  <b> Tags :</b><?php echo $tag;?><br>
                </div>
              </div>
            
            </div>
          </div>
        </div>
        <!-- /.container-fluid -->
      </div>
      <!-- End of Main Content -->
      <!-- Footer -->
      <footer class="sticky-footer bg-white">
        <div class="container my-auto">
          <div class="copyright text-center my-auto">
            <span>Copyright &copy; LcPdn 2020</span>
          </div>
        </div>
      </footer>
      <!-- End of Footer -->
    </div>
    <!-- End of Content Wrapper -->
  </div>
  <!-- End of Page Wrapper -->
  <!-- Scroll to Top Button-->
  <a class="scroll-to-top rounded" href="#page-top">
    <i class="fas fa-angle-up"></i>
  </a>
  <!-- Bootstrap core JavaScript-->
  <script src="vendor/jquery/jquery.min.js"></script>
  <script src="vendor/bootstrap/js/bootstrap.bundle.min.js"></script>
  <!-- Core plugin JavaScript-->
  <script src="vendor/jquery-easing/jquery.easing.min.js"></script>
  <!-- Custom scripts for all pages-->
  <script src="js/sb-admin-2.min.js"></script> </body> </html>
