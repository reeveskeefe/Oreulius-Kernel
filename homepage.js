import React, { useState, useEffect, useRef } from 'react';
import { 
  Terminal, 
  Cpu, 
  Shield, 
  Zap, 
  Network, 
  HardDrive, 
  Code, 
  ChevronRight, 
  Github, 
  BookOpen, 
  Menu, 
  X,
  ArrowRight,
  Play,
  FileCode,
  Layers,
  CheckCircle,
  Search,
  Command
} from 'lucide-react';

// --- Styles & Animations ---
const styles = `
  @keyframes scan {
    0% { top: 0%; opacity: 0; }
    10% { opacity: 1; }
    90% { opacity: 1; }
    100% { top: 100%; opacity: 0; }
  }
  .scan-line {
    position: absolute;
    left: 0;
    width: 100%;
    height: 2px;
    background: #6366f1;
    box-shadow: 0 0 10px #6366f1, 0 0 20px #6366f1;
    animation: scan 1.5s linear infinite;
    z-index: 10;
  }
  @keyframes grid-move {
    0% { transform: translateY(0); }
    100% { transform: translateY(24px); }
  }
  .animate-grid {
    animation: grid-move 3s linear infinite;
  }
  .typing-cursor::after {
    content: '▋';
    animation: blink 1s step-end infinite;
    margin-left: 2px;
    color: #4ade80;
  }
  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0; }
  }
  @keyframes shimmer {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(100%); }
  }
  .shimmer-effect::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
    animation: shimmer 2s infinite;
  }
`;

// --- Components ---

const Navigation = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [hoveredIndex, setHoveredIndex] = useState(null);

  const navItems = [
    { label: 'Architecture', id: 'architecture' },
    { label: 'Capabilities', id: 'capabilities' },
    { label: 'Wasm JIT', id: 'wasm-jit' },
    { label: 'Docs', id: 'docs' }
  ];

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <nav className={`fixed top-0 w-full z-50 transition-all duration-500 px-4 md:px-8 py-4`}>
      <style>{styles}</style>
      
      {/* Fancy Floating Nav Container */}
      <div className={`max-w-6xl mx-auto rounded-2xl transition-all duration-500 border ${
        scrolled 
          ? 'bg-zinc-900/70 backdrop-blur-xl border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.5)] py-2' 
          : 'bg-transparent border-transparent py-4'
      }`}>
        <div className="px-6 flex items-center justify-between">
          
          {/* Logo / Brand */}
          <div className="flex items-center space-x-3 group cursor-pointer relative overflow-hidden">
            <div className="relative">
               <div className="w-10 h-10 bg-gradient-to-br from-indigo-600 to-violet-700 rounded-xl flex items-center justify-center shadow-lg group-hover:shadow-indigo-500/40 transition-all duration-500 group-hover:rotate-6">
                <Cpu className="text-white" size={20} />
              </div>
              <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-zinc-950 rounded-full flex items-center justify-center">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_8px_#22c55e]"></div>
              </div>
            </div>
            <div className="flex flex-col">
              <span className="text-white font-bold text-lg tracking-tight leading-none">Oreulia</span>
              <span className="text-[10px] text-gray-500 font-mono tracking-widest mt-1 uppercase">Kernel Project</span>
            </div>
          </div>
          
          {/* Desktop Navigation */}
          <div className="hidden lg:flex items-center bg-white/5 rounded-full px-2 py-1 border border-white/5">
            <ul className="flex items-center space-x-1">
              {navItems.map((item, idx) => (
                <li key={item.id} className="relative">
                  <a 
                    href={`#${item.id}`} 
                    onMouseEnter={() => setHoveredIndex(idx)}
                    onMouseLeave={() => setHoveredIndex(null)}
                    className={`px-5 py-2 rounded-full text-sm font-medium transition-all duration-300 relative z-10 ${
                      hoveredIndex === idx ? 'text-white' : 'text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    {item.label}
                  </a>
                  {/* Hover Background Glow */}
                  {hoveredIndex === idx && (
                    <div 
                      className="absolute inset-0 bg-white/10 rounded-full blur-sm transition-all duration-300 z-0"
                      style={{ transform: 'scale(1.1)' }}
                    ></div>
                  )}
                </li>
              ))}
            </ul>
          </div>

          {/* Right Action Area */}
          <div className="hidden md:flex items-center space-x-4">
             {/* Command Search Bar - Visual Only */}
             <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-black/40 border border-white/5 text-gray-500 hover:border-white/20 transition-all cursor-pointer group">
                <Search size={14} />
                <span className="text-xs font-mono">Quick Search</span>
                <div className="flex items-center gap-0.5 ml-2 bg-zinc-800 px-1.5 py-0.5 rounded text-[10px] border border-white/5 group-hover:bg-zinc-700">
                  <Command size={10} />
                  <span>K</span>
                </div>
             </div>

            <a 
              href="#" 
              className="relative group overflow-hidden px-5 py-2 rounded-xl bg-indigo-600 text-white text-sm font-bold shadow-lg shadow-indigo-500/20 hover:shadow-indigo-500/40 transition-all hover:-translate-y-0.5"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000"></div>
              <div className="flex items-center gap-2">
                <Github size={16} />
                <span>Star on GitHub</span>
              </div>
            </a>
          </div>
          
          {/* Mobile Menu Toggle */}
          <div className="lg:hidden">
            <button 
              onClick={() => setIsOpen(!isOpen)} 
              className="w-10 h-10 flex items-center justify-center rounded-xl bg-white/5 border border-white/10 text-gray-400 hover:text-white transition-colors"
            >
              {isOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Drawer */}
      {isOpen && (
        <div className="lg:hidden mt-4 mx-auto max-w-6xl rounded-2xl bg-zinc-900 border border-white/10 p-6 animate-in slide-in-from-top-10 fade-in duration-300 shadow-2xl overflow-hidden">
           <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-600/10 blur-3xl rounded-full -mr-16 -mt-16"></div>
           <div className="flex flex-col space-y-4 relative z-10">
            {navItems.map((item) => (
              <a 
                key={item.id} 
                href={`#${item.id}`} 
                onClick={() => setIsOpen(false)}
                className="text-gray-300 hover:text-indigo-400 text-lg font-semibold flex items-center justify-between group"
              >
                {item.label}
                <ChevronRight size={18} className="opacity-0 group-hover:opacity-100 -translate-x-2 group-hover:translate-x-0 transition-all" />
              </a>
            ))}
            <div className="pt-4 border-t border-white/5">
                <button className="w-full py-3 rounded-xl bg-indigo-600 text-white font-bold">
                    View Project Code
                </button>
            </div>
          </div>
        </div>
      )}
    </nav>
  );
};

const InteractiveTerminal = () => {
  const [lines, setLines] = useState([
    { type: 'prompt', text: 'cpu-info' },
    { type: 'output', text: 'Vendor: GenuineIntel' },
    { type: 'output', text: 'Features: FPU VME DE PSE TSC MSR PAE MCE...' },
    { type: 'output', text: 'SIMD: SSE2 SSE3 AVX' },
  ]);
  const [currentCommand, setCurrentCommand] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (step === 0) {
      const timer = setTimeout(() => { setStep(1); setIsTyping(true); }, 2000);
      return () => clearTimeout(timer);
    }
    if (step === 1) {
      if (currentCommand.length < 'wasm-run demo.wasm'.length) {
        const timer = setTimeout(() => {
          setCurrentCommand('wasm-run demo.wasm'.slice(0, currentCommand.length + 1));
        }, 50 + Math.random() * 50);
        return () => clearTimeout(timer);
      } else {
        setStep(2);
        setIsTyping(false);
      }
    }
    if (step === 2) {
      const timer = setTimeout(() => {
        setLines(prev => [
          ...prev, 
          { type: 'prompt', text: 'wasm-run demo.wasm' },
          { type: 'output', text: '[kernel] JIT compiling module...' },
          { type: 'output', text: '[kernel] Capability \'Console.Write\' injected.' },
          { type: 'output', text: 'Hello from WebAssembly running in Ring 3!' }
        ]);
        setCurrentCommand('');
        setStep(3);
      }, 400);
      return () => clearTimeout(timer);
    }
    if (step === 3) {
      const timer = setTimeout(() => {
        setLines([
            { type: 'prompt', text: 'cpu-info' },
            { type: 'output', text: 'Vendor: GenuineIntel' },
            { type: 'output', text: 'Features: FPU VME DE PSE TSC MSR PAE MCE...' },
            { type: 'output', text: 'SIMD: SSE2 SSE3 AVX' },
        ]);
        setStep(0);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [step, currentCommand]);

  return (
    <div className="rounded-2xl overflow-hidden bg-[#0d1117] border border-white/10 shadow-2xl font-mono text-sm relative group h-[320px] flex flex-col hover:border-indigo-500/30 transition-colors duration-500">
      <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-indigo-500 to-transparent"></div>
      <div className="flex items-center px-4 py-3 border-b border-gray-800 bg-white/5 backdrop-blur-md">
        <div className="flex space-x-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/80"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/80"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-green-500/80"></div>
        </div>
        <div className="ml-4 text-gray-500 text-[10px] uppercase tracking-widest flex-1 text-center pr-8 font-bold">shell — i686</div>
      </div>
      <div className="p-6 text-gray-300 space-y-2 overflow-y-auto flex-1 font-medium bg-gradient-to-b from-transparent to-black/20">
        {lines.map((line, i) => (
          <div key={i} className={`${line.type === 'output' ? 'text-gray-400 pl-4 border-l-2 border-indigo-500/20' : ''}`}>
            {line.type === 'prompt' && (
              <span className="mr-2">
                <span className="text-indigo-400">➜</span> <span className="text-purple-400">~</span>
              </span>
            )}
            {line.text}
          </div>
        ))}
        <div className="flex">
          <span className="text-indigo-400 mr-2">➜</span>
          <span className="text-purple-400">~</span>
          <span className={`ml-2 ${!isTyping ? 'typing-cursor' : ''}`}>{currentCommand}</span>
          {isTyping && <span className="typing-cursor"></span>}
        </div>
      </div>
    </div>
  );
};

const Hero = () => {
  return (
    <div className="relative bg-zinc-950 overflow-hidden pt-40 pb-20 sm:pt-48 sm:pb-24">
      {/* Background decoration */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full pointer-events-none opacity-40">
        <div className="absolute top-[10%] left-[10%] w-[40rem] h-[40rem] bg-indigo-600/10 rounded-full blur-[120px]"></div>
        <div className="absolute bottom-[10%] right-[10%] w-[30rem] h-[30rem] bg-violet-600/10 rounded-full blur-[100px]"></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center">
        <div className="text-center md:text-left md:w-1/2 md:pr-12 z-10">
          <div className="inline-flex items-center px-3 py-1.5 rounded-full bg-white/5 border border-white/10 text-indigo-300 text-[10px] font-mono mb-8 backdrop-blur-md tracking-wider">
            <span className="flex h-1.5 w-1.5 rounded-full bg-indigo-500 mr-2 animate-pulse shadow-[0_0_8px_#6366f1]"></span>
            CURRENT BUILD: v0.4.1-ALPHA
          </div>
          <h1 className="text-5xl md:text-7xl font-extrabold text-white tracking-tight mb-8 leading-[1.1]">
            Computing <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 via-white to-indigo-400 bg-[length:200%_auto] animate-[gradient_4s_linear_infinite]">
              Redefined.
            </span>
          </h1>
          <p className="mt-4 text-xl text-gray-400 max-w-2xl mx-auto md:mx-0 font-light leading-relaxed">
            Oreulia is a Wasm-native operating system featuring in-kernel JIT compilation, unforgeable capabilities, and deterministic persistence. Built for the modern cloud.
          </p>
          <div className="mt-12 flex flex-col sm:flex-row gap-5 justify-center md:justify-start">
            <button className="px-10 py-4 rounded-xl bg-white text-black font-bold hover:shadow-[0_0_30px_rgba(255,255,255,0.2)] transition-all hover:scale-[1.02] flex items-center justify-center gap-2">
              Launch Prototype <ArrowRight size={18} />
            </button>
            <button className="px-10 py-4 rounded-xl bg-white/5 border border-white/10 text-white font-medium hover:bg-white/10 transition-all backdrop-blur-md flex items-center justify-center gap-2">
              <BookOpen size={18} /> Documentation
            </button>
          </div>
        </div>

        <div className="mt-20 md:mt-0 md:w-1/2 w-full z-10 perspective-1000">
          <div className="transform hover:scale-[1.02] transition-transform duration-700">
            <InteractiveTerminal />
          </div>
        </div>
      </div>
    </div>
  );
};

const SpotlightCard = ({ icon: Icon, title, description, badge }) => {
  const divRef = useRef(null);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [isHovered, setIsHovered] = useState(false);

  const handleMouseMove = (e) => {
    if (!divRef.current) return;
    const rect = divRef.current.getBoundingClientRect();
    setPosition({ x: e.clientX - rect.left, y: e.clientY - rect.top });
  };

  return (
    <div 
      ref={divRef}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className="relative p-8 rounded-3xl bg-zinc-900/50 border border-white/5 overflow-hidden group hover:border-indigo-500/30 transition-all duration-500"
    >
      <div 
        className="pointer-events-none absolute -inset-px opacity-0 transition duration-500 group-hover:opacity-100"
        style={{
          background: `radial-gradient(400px circle at ${position.x}px ${position.y}px, rgba(99, 102, 241, 0.15), transparent 60%)`
        }}
      />
      <div className="relative z-10">
        <div className="w-14 h-14 rounded-2xl bg-indigo-500/10 flex items-center justify-center mb-6 group-hover:scale-110 group-hover:bg-indigo-500/20 transition-all duration-500">
          <Icon className="text-indigo-400 group-hover:text-indigo-300" size={28} />
        </div>
        <div className="flex justify-between items-start mb-3">
          <h3 className="text-2xl font-bold text-white group-hover:text-indigo-100 transition-colors">{title}</h3>
          {badge && <span className="text-[9px] uppercase font-black tracking-widest bg-indigo-600/20 text-indigo-400 px-2.5 py-1 rounded-full border border-indigo-500/20">{badge}</span>}
        </div>
        <p className="text-gray-400 leading-relaxed group-hover:text-gray-300 transition-colors">
          {description}
        </p>
      </div>
    </div>
  );
};

const Features = () => {
  const features = [
    {
      icon: Shield,
      title: "Capability Model",
      description: "No ambient authority. Processes hold unforgeable handles to kernel objects. Access is granted explicitly, never assumed.",
      badge: "Core"
    },
    {
      icon: Zap,
      title: "In-Kernel JIT",
      description: "WebAssembly modules are compiled to native x86 machine code at runtime, offering near-native performance while maintaining sandboxing.",
      badge: "Performance"
    },
    {
      icon: Network,
      title: "Hybrid Stack",
      description: "A complete in-kernel TCP/IP stack including Ethernet, ARP, UDP, TCP, and DNS, supporting high-speed VirtIO drivers.",
      badge: "New"
    },
    {
      icon: HardDrive,
      title: "Durable State",
      description: "State durability is a core OS concern. Utilizing append-only logs and snapshots for crash recovery and deterministic replay.",
      badge: "Reliability"
    },
    {
      icon: Terminal,
      title: "VFS Architecture",
      description: "A hierarchical Virtual File System supporting mounts, inodes, and standard operations like open, read, and write.",
      badge: "Standard"
    },
    {
      icon: Code,
      title: "Typed IPC",
      description: "Components communicate via strictly typed, bounded channels. Capabilities can be transferred inside messages.",
      badge: "Architecture"
    }
  ];

  return (
    <div id="architecture" className="py-32 bg-zinc-950 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-24">
          <h2 className="text-indigo-500 font-black tracking-[0.2em] uppercase text-xs mb-4">The Stack</h2>
          <p className="text-4xl sm:text-5xl font-extrabold text-white mb-8 tracking-tight">Engineered for Safety</p>
          <div className="w-20 h-1.5 bg-indigo-600 mx-auto rounded-full mb-8"></div>
          <p className="text-gray-400 text-lg font-light leading-relaxed">
            Oreulia isn't just a kernel—it's a new approach to the application boundary, combining the isolation of a hypervisor with the speed of native code.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((f, i) => (
            <SpotlightCard key={i} {...f} />
          ))}
        </div>
      </div>
    </div>
  );
};

const JITSimulator = () => {
  const [activeTab, setActiveTab] = useState('wasm');
  const [isCompiling, setIsCompiling] = useState(false);
  const [compilationProgress, setCompilationProgress] = useState(0);
  const [isCompiled, setIsCompiled] = useState(false);

  const handleCompile = () => {
    setIsCompiling(true);
    setCompilationProgress(0);
    setActiveTab('wasm');
    const interval = setInterval(() => {
      setCompilationProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsCompiling(false);
          setIsCompiled(true);
          setActiveTab('asm');
          return 100;
        }
        return prev + 5;
      });
    }, 40);
  };

  const wasmCode = `(module
  (import "oreulia" "channel_send" 
    (func $send (param i32 i32 i32) (result i32))
  )
  (func (export "_start")
    i32.const 1 ;; Handle ID
    i32.const 0 ;; Data Ptr
    i32.const 12 ;; Length
    call $send
    drop
  )
)`;

  const asmCode = `; JIT Output (x86_64)
_start:
  push rbp
  mov rbp, rsp
  mov edi, 1     ; i32.const 1
  mov esi, 0     ; i32.const 0
  mov edx, 12    ; i32.const 12
  
  ; JIT Injected Trap
  mov eax, 0xSYS_SEND
  syscall
  
  pop rbp
  ret`;

  return (
    <div className="grid lg:grid-cols-2 gap-20 items-center">
      <div className="z-10">
        <h2 className="text-4xl font-extrabold text-white mb-8 leading-tight">Wasm as Native Code</h2>
        <p className="text-gray-400 mb-8 text-xl font-light leading-relaxed">
          Forget interpretation. Oreulia's JIT compiles every module directly into machine instructions. 
        </p>
        
        <div className="space-y-8">
          {[
            { title: "Dynamic Linking", desc: "Imports are resolved at load-time to direct jump offsets." },
            { title: "Sandboxed by Design", desc: "Memory access is restricted via hardware segmentation and paging." },
            { title: "Zero Latency", desc: "Compilation happens in parallel with I/O for instant start-times." }
          ].map((item, idx) => (
            <div key={idx} className="flex gap-6 group">
              <div className="flex-shrink-0 w-12 h-12 rounded-2xl bg-white/5 flex items-center justify-center border border-white/10 group-hover:bg-indigo-600 transition-all">
                <CheckCircle className="text-indigo-400 group-hover:text-white" size={20} />
              </div>
              <div>
                <h4 className="text-white text-lg font-bold mb-1">{item.title}</h4>
                <p className="text-gray-500 font-light">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
        
        <button 
          onClick={handleCompile}
          disabled={isCompiling}
          className={`mt-12 px-8 py-4 rounded-xl font-bold flex items-center gap-3 transition-all ${
            isCompiling ? 'bg-zinc-800 text-zinc-500' : 
            isCompiled ? 'bg-green-600 text-white' : 'bg-indigo-600 text-white shadow-xl shadow-indigo-600/20'
          }`}
        >
          {isCompiling ? "Compiling Module..." : isCompiled ? "Module Optimized" : "Test JIT Compiler"}
          <Play size={16} fill="currentColor" />
        </button>
      </div>

      <div className="bg-[#0b0e14] rounded-3xl overflow-hidden shadow-[0_40px_100px_rgba(0,0,0,0.6)] border border-white/5 relative h-[450px] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 bg-white/5 backdrop-blur-md border-b border-white/5">
          <div className="flex space-x-6">
            <button onClick={() => setActiveTab('wasm')} className={`text-xs font-mono uppercase tracking-widest pb-1 border-b-2 transition-all ${activeTab === 'wasm' ? 'border-indigo-500 text-white' : 'border-transparent text-gray-500'}`}>source.wat</button>
            <button onClick={() => setActiveTab('asm')} className={`text-xs font-mono uppercase tracking-widest pb-1 border-b-2 transition-all ${activeTab === 'asm' ? 'border-indigo-500 text-white' : 'border-transparent text-gray-500'}`}>native.asm</button>
          </div>
          <div className="flex gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-zinc-800"></div>
            <div className="w-2.5 h-2.5 rounded-full bg-zinc-800"></div>
          </div>
        </div>
        
        <div className="flex-1 relative p-8 font-mono text-sm overflow-hidden">
          {isCompiling && <div className="scan-line" style={{ top: `${compilationProgress}%` }}></div>}
          
          <div className={`transition-all duration-500 ${activeTab === 'wasm' ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4 pointer-events-none absolute'}`}>
             <pre className="text-gray-400 leading-relaxed">{wasmCode}</pre>
          </div>

          <div className={`transition-all duration-500 ${activeTab === 'asm' ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4 pointer-events-none absolute'}`}>
             <pre className="text-indigo-400 leading-relaxed">{asmCode}</pre>
          </div>
        </div>
      </div>
    </div>
  );
};

const CodeSection = () => {
  return (
    <div id="wasm-jit" className="py-32 bg-zinc-950 relative overflow-hidden">
       <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-indigo-500/20 to-transparent"></div>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <JITSimulator />
      </div>
    </div>
  );
};

const Footer = () => (
  <footer className="bg-black pt-24 pb-12">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="grid md:grid-cols-4 gap-16 mb-24">
        <div className="col-span-1 md:col-span-2">
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center">
              <Cpu className="text-white" size={16} />
            </div>
            <span className="text-white font-bold text-xl">Oreulia</span>
          </div>
          <p className="text-gray-500 text-lg font-light leading-relaxed max-w-sm">
            Pushing the boundaries of kernel design with WebAssembly and capability-based security.
          </p>
        </div>
        
        <div>
          <h4 className="text-white font-bold mb-6 text-sm uppercase tracking-[0.2em]">Framework</h4>
          <ul className="space-y-4 text-gray-500">
            <li><a href="#" className="hover:text-white transition-colors">OS Vision</a></li>
            <li><a href="#" className="hover:text-white transition-colors">Wasm ABI</a></li>
            <li><a href="#" className="hover:text-white transition-colors">Architecture</a></li>
          </ul>
        </div>

        <div>
          <h4 className="text-white font-bold mb-6 text-sm uppercase tracking-[0.2em]">Source</h4>
          <ul className="space-y-4 text-gray-500">
            <li><a href="#" className="hover:text-white transition-colors">GitHub Repo</a></li>
            <li><a href="#" className="hover:text-white transition-colors">Build Guide</a></li>
            <li><a href="#" className="hover:text-white transition-colors">Contributions</a></li>
          </ul>
        </div>
      </div>
      
      <div className="pt-8 border-t border-white/5 flex flex-col md:flex-row justify-between items-center text-gray-600 text-sm">
        <p>© 2026 Oreulia Kernel Project. MIT Licensed.</p>
        <div className="flex space-x-8 mt-6 md:mt-0 uppercase tracking-widest font-bold text-[10px]">
           <a href="#" className="hover:text-white transition-colors">Status</a>
           <a href="#" className="hover:text-white transition-colors">Security</a>
           <a href="#" className="hover:text-white transition-colors">Privacy</a>
        </div>
      </div>
    </div>
  </footer>
);

const App = () => {
  return (
    <div className="bg-zinc-950 min-h-screen text-gray-200 font-sans selection:bg-indigo-500 selection:text-white">
      <Navigation />
      <main>
        <Hero />
        <Features />
        <CodeSection />
      </main>
      <Footer />
    </div>
  );
};

export default App;