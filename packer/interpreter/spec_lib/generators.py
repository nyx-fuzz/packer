class FixedOptionsGenerator:
    def __init__(self,*options):
        self.options=options
    
    def msgpack(self):
        return ["Options",self.options]

def opts(*options):
    return FixedOptionsGenerator(*options)

class FixedFlagsGenerator:
    def __init__(self,*options):
        self.flags=options
    
    def msgpack(self):
        return ["Flags",self.flags]

def flags(*options):
    return FixedOptionsGenerator(*options)

class LimitsGenerator:
    def __init__(self,min,max,align):
        self.min=min
        self.max=max
        self.align = align
    
    def msgpack(self):
        return ["Limits",(self.min,self.max),self.align]
def limits(min,max,align=1):
    return LimitsGenerator(min,max,align)


class RegexGenerator:
    def __init__(self,regex_str):
        self.str = str(regex_str)
    
    def msgpack(self):
        return ["Regex",self.str]

def regex(rstr):
    return RegexGenerator(rstr)