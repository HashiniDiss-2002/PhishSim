from pyngrok import ngrok, conf

conf.get_default().auth_token = "3DoAMsYNoW0np9Eevq5aHev7Hys_6BF3qx4Ykrbi9Y5Y4dSbf"
tunnel = ngrok.connect(5000)
print("Public URL:", tunnel.public_url)
input("Press Enter to stop the tunnel...")
ngrok.disconnect(tunnel.public_url)