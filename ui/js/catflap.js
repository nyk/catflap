$(document).ready(function() {

  // Hide default text
  $('.default-value').each(function() {
      var default_value = this.value;
      $(this).focus(function() {
          if(this.value === default_value) {
              this.value = '';
          }
      });
      $(this).blur(function() {
          if(this.value === '') {
              this.value = default_value;
          }
      });
  });

  // Bind token input field with 'enter' keypress.
  $('input#passphrase').keypress(function(e) {
    if(e.which == 13) {
      var pass = $('input#passphrase').val();
      var data = {
        "random" : Math.floor(Math.random()*100000)
      };

      data.token = Sha256.hash(pass + data.random);

      $.ajax({
        url: '/catflap/knock',
        data: data,
        success: function(jsonData){
          data = JSON.parse(jsonData);
          console.log(data);
          switch (data.StatusCode) {
            case 200:
              console.log(data.StatusCode);
              $(location).attr('href',data.UrlRedirect);
              break;
            default:
              console.log(data.StatusCode);
              break;
          }
        }
      })
      .fail(function(){
        alert('fail!');
      });

    }
  });

});
