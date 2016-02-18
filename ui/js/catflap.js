(function($) { $(document).ready(function() {

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

      // Get the first word to send as the key for the pass phrase.
      // The first word is any part that comes before a special
      // character (including spaces) other than the underscore.
      var matches = pass.match(/^(\w+)\W+/);
      // If there is nothing that looks like a key then don't make
      // an authentication request.
      if (matches === null) {
        return;
      }

      // Construct our data packet to send to the server.
      var data = {
        "_key" : matches[1],
        "random" : Math.floor(Math.random()*100000)
      };
      data.token = Sha256.hash(pass + data.random);

      $.ajax({
        url: '/catflap/knock',
        data: data,
        success: function(jsonData){
          data = JSON.parse(jsonData);
          hostname = null;
          console.log(data);
          switch (data.StatusCode) {
            case 200:
              if (data.RedirectUrl == "reload") {
                location.reload(true);
              } else {
                $(location).attr('href', data.RedirectUrl);
              }
              break;
            default:
              $('#passphrase').addClass('failed');
              $('#locked-message').hide();
              $('#failed-message').show();
              break;
          }
        }
      })
      .fail(function(){
        alert(data._key);
      });

    }
  });
});
})(jQuery);
