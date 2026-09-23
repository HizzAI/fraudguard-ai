"use client";

import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { ArrowRight } from 'lucide-react';

const CyberMatrixHero = ({ onDeploy }) => {
    const canvasRef = useRef(null);
    const [isClient, setIsClient] = useState(false);

    useEffect(() => {
        setIsClient(true);
    }, []);

    useEffect(() => {
        if (!isClient) return;
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        let animationFrameId;
        
        let width = canvas.width = canvas.parentElement.clientWidth;
        let height = canvas.height = canvas.parentElement.clientHeight;
        
        // Configuration
        const gridSize = 40;
        const nodes = [];
        const numNodes = Math.floor((width * height) / 15000);
        
        for (let i = 0; i < numNodes; i++) {
            nodes.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.5,
                vy: (Math.random() - 0.5) * 0.5,
                size: Math.random() * 2 + 1,
                alpha: Math.random() * 0.5 + 0.1
            });
        }
        
        const draw = () => {
            ctx.clearRect(0, 0, width, height);
            
            // Draw subtle grid
            ctx.strokeStyle = 'rgba(30, 41, 59, 0.4)'; // slate-800 with opacity
            ctx.lineWidth = 1;
            for (let x = 0; x < width; x += gridSize) {
                ctx.beginPath();
                ctx.moveTo(x, 0);
                ctx.lineTo(x, height);
                ctx.stroke();
            }
            for (let y = 0; y < height; y += gridSize) {
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(width, y);
                ctx.stroke();
            }
            
            // Update and draw nodes
            for (let i = 0; i < nodes.length; i++) {
                const node = nodes[i];
                node.x += node.vx;
                node.y += node.vy;
                
                if (node.x < 0 || node.x > width) node.vx *= -1;
                if (node.y < 0 || node.y > height) node.vy *= -1;
                
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.size, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(56, 189, 248, ${node.alpha})`; // sky-400
                ctx.fill();
                
                // Draw connections
                for (let j = i + 1; j < nodes.length; j++) {
                    const node2 = nodes[j];
                    const dx = node.x - node2.x;
                    const dy = node.y - node2.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    
                    if (dist < 100) {
                        ctx.beginPath();
                        ctx.moveTo(node.x, node.y);
                        ctx.lineTo(node2.x, node2.y);
                        ctx.strokeStyle = `rgba(56, 189, 248, ${0.2 * (1 - dist / 100)})`;
                        ctx.stroke();
                    }
                }
            }
            
            animationFrameId = requestAnimationFrame(draw);
        };
        
        draw();
        
        const handleResize = () => {
            width = canvas.width = canvas.parentElement.clientWidth;
            height = canvas.height = canvas.parentElement.clientHeight;
        };
        
        window.addEventListener('resize', handleResize);
        
        return () => {
            cancelAnimationFrame(animationFrameId);
            window.removeEventListener('resize', handleResize);
        };
    }, [isClient]);

    const fadeUpVariants = {
        hidden: { opacity: 0, y: 20 },
        visible: (i) => ({
            opacity: 1,
            y: 0,
            transition: {
                delay: i * 0.1,
                duration: 0.8,
                ease: "easeOut",
            },
        }),
    };

    return (
        <div className="relative h-[60vh] min-h-[500px] w-full bg-[#0b0f19] flex flex-col items-center justify-center overflow-hidden rounded-xl border border-slate-800">
            <canvas ref={canvasRef} className="absolute inset-0 z-0 pointer-events-none opacity-60" />
            
            <div className="relative z-10 text-center p-8 bg-[#0b0f19]/60 backdrop-blur-sm rounded-2xl border border-slate-800/50 shadow-2xl max-w-3xl w-full mx-4">
                <motion.div
                    custom={0}
                    variants={fadeUpVariants}
                    initial="hidden"
                    animate="visible"
                    className="flex justify-center mb-6"
                >
                    <div className="w-16 h-16 bg-blue-900/30 rounded-2xl flex items-center justify-center border border-blue-500/30 shadow-[0_0_30px_rgba(37,99,235,0.2)]">
                        <img src="/fraudguard-logo.svg" alt="FraudGuard AI Symbol" className="w-10 h-10 drop-shadow-[0_0_10px_rgba(56,189,248,0.6)]" />
                    </div>
                </motion.div>

                <motion.h1
                    custom={1}
                    variants={fadeUpVariants}
                    initial="hidden"
                    animate="visible"
                    className="text-5xl md:text-6xl font-bold tracking-tight mb-4 text-white"
                >
                    FraudGuard <span className="bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-cyan-300">AI</span>
                </motion.h1>

                <motion.p
                    custom={2}
                    variants={fadeUpVariants}
                    initial="hidden"
                    animate="visible"
                    className="max-w-2xl mx-auto text-lg text-slate-400 mb-10"
                >
                    Advanced Android Malware Static Analysis & Risk Assessment.
                </motion.p>

                <motion.div
                    custom={3}
                    variants={fadeUpVariants}
                    initial="hidden"
                    animate="visible"
                >
                    <button 
                        onClick={onDeploy}
                        className="px-8 py-4 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg shadow-[0_0_20px_rgba(37,99,235,0.4)] hover:shadow-[0_0_30px_rgba(56,189,248,0.6)] transition-all duration-300 flex items-center gap-2 mx-auto"
                    >
                        Begin Investigation
                        <ArrowRight className="h-5 w-5" />
                    </button>
                </motion.div>
            </div>
            
            {/* Subtle bottom gradient */}
            <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-[#0b0f19] to-transparent pointer-events-none z-0" />
        </div>
    );
};

export default CyberMatrixHero;
