class YouTube < Liquid::Tag
    Syntax = /^\s*([^\s]+)(\s+(\d+)\s+(\d+)\s*)?/
  
    def initialize(tagName, markup, tokens)
      super
  
      if markup =~ Syntax then
        @id = $1
  
        if $2.nil? then
            @width = 560
            @height = 315
        else
            @width = $2.to_i
            @height = $3.to_i
        end
      else
        raise "No YouTube ID provided in the \"youtube\" tag"
      end
    end
  
    def render(context)
       "<div class=\"video-container\" style=\"position: relative; width: 100%;padding-bottom: 56.25%;padding-top: 25px;height:0;margin-bottom:10px;\"><iframe style=\"position: absolute;top:0;left:0;width:100%;height:100%;border=0;\" src=\"http://www.youtube.com/embed/#{@id}\" frameborder=\"0\" allowfullscreen></iframe></div>"    
    end
  
    Liquid::Template.register_tag "youtube", self
  end