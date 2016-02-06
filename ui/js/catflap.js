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
  $('input#token').keypress(function(e) {
    if(e.which == 13) {
      var pass = $('input#token').val();
      var salt = Math.floor(Math.random()*100000);
      var token = Sha256.hash(pass + salt);

      $.ajax({
        url: url,
        data: data,
        success: success,
        dataType: dataType
      });

    }
  });

});
