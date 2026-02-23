# hello_world.rb

file '/tmp/hello.txt' do
  content 'Hello, World!'
  action :create
end
