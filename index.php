<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

require_once 'src/mcrypt.php';

use normalApi\mcrypt;

$data = 'hello world';
echo $data.'<br>';
$mcrypt = new mcrypt();

$data_encode = $mcrypt->encode($data);
echo $data_encode.'<br>';

$data_decode = $mcrypt->decode($data_encode);
echo $data_decode.'<br>';